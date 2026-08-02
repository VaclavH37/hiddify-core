package config

import (
	context "context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"strings"
	sync "sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/hutils"
	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group/balancer"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/wireguard-go/hiddify"
)

const (
	DNSRemoteTag           = "dns-remote"
	DNSRemoteTagFallback   = "dns-remote-fallback"
	DNSLocalTag            = "dns-local"
	DNSStaticTag           = "dns-static"
	DNSDirectTag           = "dns-direct"
	DNSCNDirectTag         = "dns-cn-direct"
	DNSCNDirectTagFallback = "dns-cn-direct-fallback"
	DNSRemoteNoWarpTag     = "dns-remote-no-warp"
	// DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"
	// DNSMultiDirectTag  = "dns-multi-direct"
	// DNSMultiRemoteTag  = "dns-multi-remote"
	DNSMultiDirectTag = "dns-direct"
	DNSMultiRemoteTag = "dns-remote"

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "lowest"
	OutboundRoundRobinTag     = "balance"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	WARPConfigTag = "🔒 WARP"

	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in"
	InboundTProxy    = "tproxy-in"
	InboundRedirect  = "redirect-in"
	InboundDirectTag = "dns-in"
)

var (
	OutboundMainDetour       = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	PredefinedOutboundTags   = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag, WARPConfigTag}
)

// TODO include selectors
func BuildConfig(ctx context.Context, hopts *HiddifyOptions, inputOpt *ReadOptions) (*option.Options, error) {

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)

	setLog(&options, hopts)
	setInbound(&options, hopts)
	staticIPs := make(map[string][]string)
	// Bootstrap IPs for the CN-direct DoH servers in setDns() so they have a
	// known-good resolution path without depending on UDP/53. doh.pub is the
	// primary (Tencent DNSPod); dns.alidns.com is the fallback (Alibaba) used
	// when doh.pub fails, so the China-direct optimization survives a single
	// provider outage instead of silently degrading to the proxy resolver.
	staticIPs["doh.pub"] = []string{"1.12.12.12", "120.53.53.53"}
	staticIPs["dns.alidns.com"] = []string{"223.5.5.5", "223.6.6.6"}
	// staticIPs["api.cloudflareclient.com"] = []string{"104.16.192.82", "2606:4700::6810:1854", getRandomWarpIP()}
	//
	// NTP was configured here (a `setNTP` helper pointing at time.apple.com, plus an
	// `enable-ntp` option). The call was already commented out upstream, so
	// options.NTP was always nil, and everything downstream of it was unreachable:
	// the `forceDirectRoute` list could only ever be populated from options.NTP.Server,
	// so the DNS rule and route rule gated on it never appeared in a built config.
	// `enable-ntp` was never read at all — setNTP hardcoded Enabled: true. All of it
	// is gone rather than left looking configurable.
	//
	// What it was for: sing-box uses NTP to correct a skewed device clock so TLS
	// certificate validity checks pass. That protection is currently absent — a device
	// with a badly wrong clock will fail handshakes. Re-adding it means restoring the
	// NTP options block AND forcing the time server direct at both the DNS and route
	// layer, because a clock too wrong for TLS is also too wrong to reach the server
	// through a TLS-based tunnel.
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}
	if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, hopts); err != nil {
		return nil, err
	}

	return &options, nil
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

// normalizeBalancerStrategy keeps an unusable strategy string from reaching the
// balancer, which rejects anything it does not recognise with "unknown load
// balance strategy" — a service-start failure, not a config-build error, so it
// surfaces far from its cause and only once a profile has more than one outbound.
//
// The empty string was the common case: HiddifyOptions loaded from a file
// unmarshal into a zero struct rather than over DefaultHiddifyOptions(), so any
// options JSON omitting "balancer-strategy" produced one.
//
// Unknown values fall back rather than erroring because this group is optional —
// it is only reachable if the user selects Auto-Rotate, and the selector defaults
// to the url-test group. Refusing to start the whole tunnel over it would trade a
// degraded optional feature for a total outage.
func normalizeBalancerStrategy(strategy string) string {
	switch strategy {
	case balancer.StrategyRoundRobin,
		balancer.StrategyConsistentHashing,
		balancer.StrategyStickySessions,
		balancer.StrategyLowestDelay:
		return strategy
	default:
		return balancer.StrategyRoundRobin
	}
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	// OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	OutboundMainDetour = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	hasPsiphon := false
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom:
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if out.Type == C.TypePsiphon {
				if hasPsiphon {
					continue
				}
				hasPsiphon = true
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
			}
			// OutboundWARPConfigDetour = OutboundSelectTag
			out = *patchHiddifyWarpFromConfig(&out, *opt)
			outbounds = append(outbounds, out)
		}
	}

	if opt.Warp.EnableWarp {
		// wg := getOrGenerateWarpLocallyIfNeeded(&opt.Warp)

		// out, err := GenerateWarpSingbox(wg, opt.Warp.CleanIP, opt.Warp.CleanPort, &option.WireGuardHiddify{
		// 	FakePackets:      opt.Warp.FakePackets,
		// 	FakePacketsSize:  opt.Warp.FakePacketSize,
		// 	FakePacketsDelay: opt.Warp.FakePacketDelay,
		// 	FakePacketsMode:  opt.Warp.FakePacketMode,
		// })
		out, err := GenerateWarpSingboxNew("p1", &hiddify.NoiseOptions{})
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = WARPConfigTag
		if opts, ok := out.Options.(*option.WARPEndpointOptions); ok {
			if opt.Warp.Mode == "warp_over_proxy" {
				opts.Detour = OutboundSelectTag
				opts.MTU = 1280
			} else {
				opts.Detour = OutboundDirectTag
				opt.MTU = max(opt.MTU, 1340)
			}

		}

		OutboundMainDetour = WARPConfigTag
		// patchWarp(out, opt, true, nil)
		out, err = patchEndpoint(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, *out)
	}
	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		if opt.Warp.EnableWarp {
			if end.Type == C.TypeWARP {
				if opts, ok := end.Options.(*option.WARPEndpointOptions); ok {
					if opts.UniqueIdentifier == "p1" {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
			if end.Type == C.TypeWireGuard {
				if opts, ok := end.Options.(*option.WireGuardEndpointOptions); ok {
					if opts.PrivateKey == opt.Warp.WireguardConfig.PrivateKey {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}

		if !strings.Contains(out.Tag, "§hide§") {
			tags = append(tags, out.Tag)
		}

		endpoints = append(endpoints, *out)
	}
	if len(opt.ConnectionTestUrls) == 0 {
		// !!! Every HOSTNAME here is force-pinned to the CN-direct resolver
		// (doh.pub) by addForceDirect() in dns.go, with a 24h TTL, and that
		// answer is shared with ordinary browser traffic. So a probe host MUST
		// resolve CORRECTLY via a mainland resolver. NEVER put a GFW-poisoned
		// domain here — Google/gstatic/YouTube etc. return poisoned addresses
		// that then break real page loads, not just the probe.
		// IP literals are exempt (getHostnameIfNotIP skips them) and are the
		// safest choice. HTTPS only.
		opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl, "https://1.1.1.1", "https://captive.apple.com/hotspot-detect.html"}
		if isBlockedConnectionTestUrl(opt.ConnectionTestUrl) {
			opt.ConnectionTestUrls = []string{opt.ConnectionTestUrl}
		}
	}
	// `lowest` uses the STANDARD sing-box url-test group, not the custom `balancer`.
	// Rationale: the custom balancer's `Tolerance` is unimplemented, so lowest-delay
	// re-selected on any millisecond of probe jitter and (with interrupt=true) tore down
	// every live connection each time — the "page loads then stalls" symptom. The url-test
	// group's `Tolerance` is a real hysteresis band: URLTestGroup.Select keeps the current
	// exit unless a candidate is more than `tolerance` ms faster. This fix is config-only
	// (both types already exist in the imported sing-box), and does not fork it.
	//
	// `InterruptExistConnections: false`: automatic re-selection must not drop live
	// connections — existing ones ride the previous exit to completion; only new
	// connections use the newly selected one. Manual switches via `select` still interrupt.
	urlTest := option.Outbound{
		Type: C.TypeURLTest,
		Tag:  OutboundURLTestTag,
		Options: &option.URLTestOutboundOptions{
			Outbounds:                 tags,
			URL:                       opt.ConnectionTestUrl,
			URLs:                      opt.ConnectionTestUrls,
			Interval:                  badoption.Duration(opt.URLTestInterval.Duration()),
			IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			Tolerance:                 opt.URLTestTolerance,
			InterruptExistConnections: false,
		},
	}

	balancerOutbound := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundRoundRobinTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            tags,
			Strategy:             normalizeBalancerStrategy(opt.BalancerStrategy),
			DelayAcceptableRatio: 2,
			// Round-robin ignores Tolerance (unimplemented in the balancer anyway); the
			// meaningful change here is not interrupting live connections on re-selection.
			InterruptExistConnections: false,
		},
	}
	defaultSelect := tags[0]

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}

	selectorTags := tags
	if len(tags) > 1 {
		if OutboundMainDetour == WARPConfigTag {
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag}, selectorTags...)
			defaultSelect = urlTest.Tag
		} else {
			// DIAGNOSTIC — TEMPORARY, REVERT ME.
			//
			// The `balance` group is omitted to test whether it is what makes the
			// tunnel start and immediately die on sing-box 1.14. The failing run
			// loops on:
			//
			//     outbound/balancer[balance]: starting load balance, monitoring enabled: true
			//     monitoring: starting outbound monitoring initialize
			//     network: updated default interface Wi-Fi, index 6
			//
			// 1.14 newly wires outbound monitoring INTO the balancer ("monitoring
			// enabled: true"), and that pairing is what repeats. Note monitoring
			// itself is on by DEFAULT in 1.14 — removing the experimental.monitoring
			// block does not disable it, which is why the earlier diagnostic proved
			// nothing.
			//
			// Safe for a default connect: defaultSelect is urlTest.Tag below, so the
			// balancer is constructed but unreachable unless the user picks
			// Auto-Rotate. Omitting it costs only that option, for this experiment.
			//
			// Restore by reverting this commit.
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag}, selectorTags...)
			_ = balancerOutbound
			// Default the selector to the lowest-latency group rather than the
			// round-robin balancer: a stable, fastest exit gives the best
			// first-connection experience and avoids mid-session IP rotation.
			// Auto-Rotate (balancer.Tag) stays in selectorTags, so users can
			// still opt into it.
			defaultSelect = urlTest.Tag

		}
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector}, outbounds...)

	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:     OutboundDirectTag,
				Type:    C.TypeDirect,
				Options: &option.DirectOutboundOptions{},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						TCPFastOpen: false,

						// TLSFragment: option.TLSFragmentOptions{
						// 	Enabled: true,
						// 	Size:    opt.TLSTricks.FragmentSize,
						// 	Sleep:   opt.TLSTricks.FragmentSleep,
						// },
					},
				},
			},
		}...,
	)

	return nil
}

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		// HTTPS only, and NO GFW-poisoned hostnames — see the matching list in
		// setOutbounds for why (these hosts get pinned to the CN-direct resolver
		// and the poisoned answer leaks into normal browsing).
		hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl, "https://1.1.1.1", "https://captive.apple.com/hotspot-detect.html"}
		if isBlockedConnectionTestUrl(hopt.ConnectionTestUrl) {
			hopt.ConnectionTestUrls = []string{hopt.ConnectionTestUrl}
		}
	}
	if hopt.EnableClashApi {
		if hopt.ClashApiSecret == "" {
			hopt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{
				Enabled: true,
			},
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", hopt.ClashApiPort),
				Secret:             hopt.ClashApiSecret,
			},

			CacheFile: &option.CacheFileOptions{
				Enabled: true,
				// FakeIP is disabled (hub runs domainStrategy:AsIs and needs real
				// IPs), so do not persist a synthetic 198.18.x.x map — a stale
				// cache would otherwise resolve against fake addresses after upgrade.
				StoreFakeIP:     false,
				StoreRDRC:       true,
				StoreWARPConfig: true,
				Path:            "data/clash.db",
			},

			Monitoring: &option.MonitoringOptions{
				URLs:           hopt.ConnectionTestUrls,
				Interval:       badoption.Duration(hopt.URLTestInterval.Duration()),
				DebounceWindow: badoption.Duration(time.Millisecond * 500),
				IdleTimeout:    badoption.Duration(hopt.URLTestInterval.Duration().Nanoseconds() * 3),
			},
		}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    false,
		DisableColor: true,
	}
}

// isIPv6Supported reports whether the HOST has a usable IPv6 stack. It says
// nothing about whether the tunnel can carry IPv6 — see tunnelIPv6Enabled.
func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

// tunnelIPv6Enabled reports whether the TUN inbound claims an IPv6 address, and
// therefore whether IPv6 traffic is captured by the tunnel at all rather than
// leaving over the host's native route.
//
// Two conditions, only the first of which is live today:
//
//  1. the host has a usable IPv6 stack, and
//  2. the exit can actually carry IPv6 to the internet.
//
// (2) is assumed true. When hub IPv6 egress becomes real, gate it HERE — this
// is deliberately the single place that decides, so the policy cannot drift
// from the address assignment in setInbound. The likely shape is a
// `TunnelIPv6` field on RouteOptions fed from the subscription (the hub knows
// its own egress capability) rather than from a user setting.
//
// If it ever does become user-facing, wire the setting to THIS function and add
// a test asserting the tun address list changes with it. The previous
// `ipv6-mode` control was serialised, shipped over gRPC and persisted while
// being read by nothing, which is worse than offering no control at all —
// users believed "IPv6: disable" protected them and it did nothing.
func tunnelIPv6Enabled(hopt *HiddifyOptions) bool {
	if !isIPv6Supported() {
		return false
	}
	// Condition (2): hub IPv6 egress. Unconditional for now.
	_ = hopt
	return true
}

func setInbound(options *option.Options, hopt *HiddifyOptions) {
	// Distinct questions, deliberately distinct variables: what the tunnel
	// captures vs what the local listener can bind to.
	tunIPv6 := tunnelIPv6Enabled(hopt)
	hostIPv6 := isIPv6Supported()
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:       hopt.TUNStack,
			MTU:         hopt.MTU,
			AutoRoute:   true,
			StrictRoute: hopt.StrictRoute,

			// EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",

		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}
		// Claiming an IPv6 address here is what makes AutoRoute install a ::/0
		// route into the tun. Without it the host keeps its native IPv6 route
		// and IPv6 traffic bypasses the tunnel entirely.
		opts.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/28")}
		if tunIPv6 {
			opts.Address = append(opts.Address, netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
		}

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		// Host capability, not tunnel policy: this is which local address the
		// mixed inbound listens on.
		if hostIPv6 {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		// Also host capability: binding the loopback listener to ::1.
		if hostIPv6 {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		options.Inbounds = append(
			options.Inbounds,
			option.Inbound{
				Type: C.TypeMixed,
				Tag:  InboundMixedTag + bind,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &addr,
						ListenPort: hopt.MixedPort,
						// InboundOptions: option.InboundOptions{
						// 	SniffEnabled:             true,
						// 	SniffOverrideDestination: true,
						// 	DomainStrategy:           inboundDomainStrategy,
						// },
					},
					SetSystemProxy: hopt.SetSystemProxy,
				},
			},
		)
		if C.IsLinux && !C.IsAndroid && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

func setRoutingOptions(options *option.Options, hopt *HiddifyOptions) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	// if opt.EnableTun && runtime.GOOS == "android" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,

	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			Inbound:     []string{InboundTUNTag},
	// 	// 			PackageName: []string{"app.hiddify.com"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }
	// if opt.EnableTun && runtime.GOOS == "windows" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,
	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			ProcessName: []string{"Hiddify", "Hiddify.exe", "HiddifyCli", "HiddifyCli.exe"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }

	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSStaticTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	forceDirectRules, err := addForceDirect(options, hopt)
	if err != nil {
		return err
	}

	dnsRules = append(dnsRules, forceDirectRules...)

	// Explicit sniffer list, deliberately WITHOUT "quic".
	//
	// The default packet sniffers include QUICClientHello, which returns
	// ErrNeedMoreData on a fragmented QUIC client hello (Chrome's is routinely
	// fragmented). sing-box then re-reads with a fresh C.ReadPayloadTimeout
	// (300ms) deadline, so the packet sits in the sniffer instead of reaching the
	// UDP/443 reject rule below. Measured: only 4 of ~25 QUIC attempts reached
	// the reject; 21 stalled in the sniffer and 16 died on i/o timeout at ~300ms.
	// That produces exactly the slow, packet-loss-style fallback the reject rule
	// exists to avoid (its method=default ICMP unreachable is meant to bounce the
	// client to TCP instantly).
	//
	// Dropping the QUIC sniffer costs the SNI on QUIC flows only. Direct/in-region
	// QUIC is unaffected because direct-regional-ips is an IP rule-set and still
	// matches without a domain; everything else is bound for the tunnel and is
	// rejected anyway. TCP sniffing (tls/http) and DNS sniffing are untouched —
	// "dns" is required by the hijack-dns rule that follows.
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
				SniffOptions: option.RouteActionSniff{
					Sniffer: badoption.Listable[string]{
						C.ProtocolTLS,
						C.ProtocolHTTP,
						C.ProtocolDNS,
						C.ProtocolSTUN,
					},
				},
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Protocol: []string{C.ProtocolDNS},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeHijackDNS,
			},
		},
	})

	// Removed: an upstream rule forcing 10.10.34.0/24 + 2001:4188:2:600::/120 to
	// the proxy. Those are Iranian filternet block-page sentinel addresses — an
	// upstream artifact with no meaning for this build. Keeping it sent any user
	// whose LAN happens to use 10.10.34.0/24 through the tunnel, where the hub
	// blackholes geoip:private and the connection dies with no useful error.
	// DNS-level poison filtering (dns/blocked_checker.go) and the WARP endpoint
	// checks (isBlockedIP / isBlockedDomain) are independent and unaffected.
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Direct",
	// 		Outbound:  OutboundDirectTag,
	// 	},
	// },
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Global",
	// 		Outbound:  OutboundMainProxyTag,
	// 	},
	// },	}

	if hopt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	// for _, rule := range opt.Rules {
	// 	routeRule := rule.MakeRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		routeRule.Outbound = OutboundBypassTag
	// 	case "block":
	// 		routeRule.Outbound = OutboundBlockTag
	// 	case "proxy":
	// 		routeRule.Outbound = OutboundMainProxyTag
	// 	}

	// 	if routeRule.IsValid() {
	// 		routeRules = append(
	// 			routeRules,
	// 			option.Rule{
	// 				Type:           C.RuleTypeDefault,
	// 				DefaultOptions: routeRule,
	// 			},
	// 		)
	// 	}

	// 	dnsRule := rule.MakeDNSRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		dnsRule.Server = DNSDirectTag
	// 	case "block":
	// 		dnsRule.Server = DNSBlockTag
	// 		dnsRule.DisableCache = true
	// 	case "proxy":
	// 		if opt.EnableFakeDNS {
	// 			fakeDnsRule := dnsRule
	// 			fakeDnsRule.Server = DNSFakeTag
	// 			fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
	// 			dnsRules = append(dnsRules, fakeDnsRule)
	// 		}
	// 		dnsRule.Server = DNSRemoteTag
	// 	}
	// 	dnsRules = append(dnsRules, dnsRule)
	// }
	// A `forceDirectRoute` list used to be built here, then consumed by a DNS rule
	// (→ dns-direct) and a route rule (→ direct outbound). It was only ever populated
	// from options.NTP.Server, and NTP is not configured (see BuildConfig), so the
	// list was always empty and neither rule was ever appended. Both are gone with the
	// NTP wiring that fed them.
	//
	// Note this was the ONLY DNS rule that routed queries to `dns-direct`. That server
	// is still registered and still needed: it is the domain_resolver for
	// dns-trick-direct, and for dns-remote whenever `remote-dns-address` is overridden
	// to a hostname rather than an IP literal. It resolves other resolvers' hostnames;
	// nothing routes ordinary queries to it.

	// parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	// if err == nil {
	// 	dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 		Domain:       []string{parsedURL.Host},
	// 		Server:       DNSRemoteTag,
	// 		RewriteTTL:   &dnsCPttl,
	// 		DisableCache: false,
	// 	})
	// }

	// NXDOMAIN, not REFUSED: REFUSED reads as "this resolver won't serve you",
	// so clients treat it as a resolver fault and retry / fail over to their own
	// DNS (a retry storm on ad-heavy pages). NXDOMAIN is the correct "this name
	// does not resolve" negative answer for a blocklist hit.
	rejectRCode := (option.DNSRCode(sdns.RcodeNameError))
	rejectDnsAction := option.DNSRuleAction{
		Action: C.RuleActionTypePredefined,
		PredefinedOptions: option.DNSRouteActionPredefined{
			Rcode: &rejectRCode,
		},
	}
	// Blocklists are BUNDLED, not fetched. These six used to be Type:Remote pulled
	// from raw.githubusercontent.com/hiddify/hiddify-geo with DownloadDetour:select
	// — i.e. over the tunnel, on first connect, from a host that is awkward to reach
	// on a CN cold start. That was the last remote rule-set fetch in the client and
	// the last runtime dependency on a Hiddify-branded URL. The dependency now lives
	// at build time only (`make fetch-rulesets`), exactly like the CN sets.
	//
	// Bundling costs nothing in memory: a remote rule-set is downloaded, cached and
	// then compiled into the same matcher structures as a local one. Measured heap
	// for all six is ~1.75 MiB against a 30 MB Go soft limit on iOS — and it was
	// already being paid, since block-ads defaults on.
	//
	// Registration stays INSIDE this branch rather than joining the unconditional
	// chinaRulesets: a user who turns the toggle off then pays no memory at all, and
	// a missing/corrupt .srs cannot stop the core from starting for them. Local
	// rule-sets are opened at config-load time, so a bad file IS fatal when enabled —
	// which is why the extractor verifies sha256 against MANIFEST and re-extracts.
	//
	// Local file names are neutral (block-*, matching the direct-* convention) so the
	// asset listing does not advertise the upstream project. Names must stay in sync
	// across three places: the curl targets in the root Makefile's fetch-rulesets,
	// the FILES array in scripts/regen_rulesets_manifest.sh, and the Path literals
	// here. Upstream source -> local name:
	//   geosite-category-ads-all -> block-ads
	//   geosite-malware          -> block-malware
	//   geosite-phishing         -> block-phishing
	//   geosite-cryptominers     -> block-cryptominers
	//   geoip-malware            -> block-malware-ips
	//   geoip-phishing           -> block-phishing-ips
	if hopt.BlockAds {
		blockRulesets := []option.RuleSet{
			{
				Tag: "block-ads", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-ads.srs"},
			},
			{
				Tag: "block-malware", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-malware.srs"},
			},
			{
				Tag: "block-phishing", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-phishing.srs"},
			},
			{
				Tag: "block-cryptominers", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-cryptominers.srs"},
			},
			{
				Tag: "block-malware-ips", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-malware-ips.srs"},
			},
			{
				Tag: "block-phishing-ips", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
				LocalOptions: option.LocalRuleSet{Path: "rulesets/block-phishing-ips.srs"},
			},
		}
		rulesets = append(rulesets, blockRulesets...)

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"block-ads",
						"block-malware",
						"block-phishing",
						"block-cryptominers",
						"block-malware-ips",
						"block-phishing-ips",
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
		// DOMAIN-only sets here. Including a geoip set in a DNS rule makes sing-box
		// resolve every query just to get an IP to test against it — the same leak
		// documented for direct-regional-ips on the China-direct path. The two
		// block-*-ips sets stay in the route rule above, where a real destination IP
		// already exists.
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				RuleSet: []string{
					"block-ads",
					"block-malware",
					"block-phishing",
					"block-cryptominers",
				},
			},
			DNSRuleAction: rejectDnsAction,
		})
	}

	// China-optimized routing — always on. Sends private + apple-cn + cn direct,
	// blocks QUIC outbound (browsers fall back gracefully); non-CN A/AAAA queries
	// resolve for real over the tunnel (dns-remote) so the hub receives IPs.
	// Rule-sets are bundled into the AAB and extracted onto the
	// Go core's BasePath by lib/core/rulesets/ruleset_extractor.dart — see
	// RULESETS.md for the refresh workflow. Two upstream entries that the
	// previous remote-fetch config silently 404'd on (sing-geoip/geoip-private
	// and sing-geosite/geosite-microsoft@cn — neither exists on SagerNet's
	// rule-set branch) have been dropped.
	chinaRulesets := []option.RuleSet{
		{
			Tag: "direct-private", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: "rulesets/direct-private.srs"},
		},
		{
			Tag: "direct-apple", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: "rulesets/direct-apple.srs"},
		},
		{
			Tag: "direct-regional-sites", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: "rulesets/direct-regional-sites.srs"},
		},
		{
			Tag: "direct-regional-ips", Type: C.RuleSetTypeLocal, Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: "rulesets/direct-regional-ips.srs"},
		},
	}
	chinaDirectTags := []string{
		"direct-private",
		"direct-apple",
		"direct-regional-sites",
		"direct-regional-ips",
	}
	// DNS rules must match by DOMAIN only. Including the geoip set
	// (direct-regional-ips) in a DNS rule makes sing-box optimistically route
	// every query to the CN-direct resolver to fetch an IP to test against
	// geoip-cn, leaking every foreign domain to doh.pub/AliDNS before it falls
	// through to FakeIP. geoip-cn stays in the route rule only (it matches the
	// real destination IP of a connection — no DNS query involved).
	chinaDirectDNSTags := []string{
		"direct-private",
		"direct-apple",
		"direct-regional-sites",
	}

	rulesets = append(rulesets, chinaRulesets...)

	// direct-regional-sites is upstream geosite-cn, which bundles the "google-cn"
	// domain set. Those hostnames are NOT genuinely CN-served — they are
	// GFW-poisoned — so treating them as CN-direct failed twice over: doh.pub
	// answered ssl.gstatic.com / update.googleapis.com / clientservices.googleapis.com
	// with 220.181.174.x, and the matching route rule then dialled that direct.
	// Keep the Google family on the remote resolver and the tunnel.
	//
	// Ordering is load-bearing: the DNS rule must precede the CN-direct DNS rules
	// below, and the route side is expressed as an EXCLUSION on the direct rule
	// (not a route-to-tunnel rule of its own) so these connections still fall
	// through to the `resolve` action — a terminal rule here would hand the hub a
	// domain name instead of an address.
	googleRemoteSuffixes := []string{
		"gstatic.com",
		"googleapis.com",
		"googleusercontent.com",
		"googlevideo.com",
		"googletagmanager.com",
		"google-analytics.com",
		"ggpht.com",
		"ytimg.com",
		// Google cert PKI / load-balancer apexes: geosite-cn lists these in its
		// google-cn set, but the GFW poisons them (c.pki.goog resolved to a China
		// Telecom IP, 220.181.174.x, and was routed direct). pki.goog is Google's
		// OCSP/CRL; l.google.com is the LB apex those PKI names CNAME under. All
		// of .goog / *.l.google.com is Google and blocked in CN, so tunnelling is
		// unconditionally correct.
		"pki.goog",
		"l.google.com",
	}
	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{DomainSuffix: googleRemoteSuffixes},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSMultiRemoteTag,
				RewriteTTL:     &REMOTE_DNS_TTL,
				BypassIfFailed: false,
			},
		},
	})

	// DNS: send these domains direct via a CN-reachable DoH endpoint. The
	// default DirectDnsAddress (1.1.1.1) is GFW-poisoned, so apple-cn /
	// microsoft-cn / geosite-cn lookups need a resolver that actually answers
	// inside CN. Two rules form a primary→fallback chain: BypassIfFailed lets a
	// failed lookup fall through to the next rule, so doh.pub (Tencent) is tried
	// first, then dns.alidns.com (Alibaba), and only if both fail does the query
	// reach a remote (proxy) DNS rule. This keeps the optimization alive through
	// a single-provider outage instead of silently degrading to the proxy.
	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{RuleSet: chinaDirectDNSTags},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSCNDirectTag,
				RewriteTTL:     &DEFAULT_DNS_TTL,
				BypassIfFailed: true,
			},
		},
	})
	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{RuleSet: chinaDirectDNSTags},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSCNDirectTagFallback,
				RewriteTTL:     &DEFAULT_DNS_TTL,
				BypassIfFailed: true,
			},
		},
	})
	// Route: same destinations bypass the proxy — EXCEPT the Google family, which
	// geosite-cn wrongly includes (see googleRemoteSuffixes above). Expressed as
	// "in the CN rule-sets AND NOT a Google suffix" so Google traffic falls
	// through to the `resolve` action and then the tunnel, rather than being
	// routed direct into a poisoned answer.
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeLogical,
		LogicalOptions: option.LogicalRule{
			RawLogicalRule: option.RawLogicalRule{
				Mode: C.LogicalTypeAnd,
				Rules: []option.Rule{
					{
						Type:           C.RuleTypeDefault,
						DefaultOptions: option.DefaultRule{RawDefaultRule: option.RawDefaultRule{RuleSet: chinaDirectTags}},
					},
					{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultRule{
							RawDefaultRule: option.RawDefaultRule{DomainSuffix: googleRemoteSuffixes, Invert: true},
						},
					},
				},
			},
			RuleAction: option.RuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{Outbound: OutboundDirectTag},
			},
		},
	})

	// FakeIP removed: the hub runs domainStrategy:AsIs, so non-CN A/AAAA queries
	// must resolve to real addresses (handled by the terminal dns-remote rule
	// below), not synthetic 198.18.x.x. See the resolve route rule that follows.

	if hopt.Region != "other" {
		// Catch-all for any .<region> domain not covered by the rule-sets
		// above. DNS lookup goes via the CN-reachable DoH server (same
		// poisoning rationale as the China-direct block above); routing dials
		// direct. Rule-set–keyed lookups for geosite-cn / geoip-cn are already
		// handled by the chinaRulesets block, which now ships those rule-sets
		// as bundled local data.
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				DomainSuffix: []string{"." + hopt.Region},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSCNDirectTag,
						RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: true,
				},
			},
		})
		// Fallback to Alibaba DoH if doh.pub fails (same primary→fallback chain
		// as the chinaDirectTags rules above).
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				DomainSuffix: []string{"." + hopt.Region},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSCNDirectTagFallback,
						RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: true,
				},
			},
		})
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					DomainSuffix: []string{"." + hopt.Region},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	// Resolve tunnel-bound domains to real IPs client-side before they reach the
	// hub. The hub runs domainStrategy:AsIs and would otherwise receive a sniffed
	// domain name (see the sniff rule above) and resolve it hub-side, breaking
	// exit-local CDN edge selection. This runs AFTER the direct/.cn/private/Apple/
	// regional rules, so those terminal route rules leave first and only
	// tunnel-bound traffic is resolved here; it is a no-op when the destination is
	// already an address. Server is dns-remote explicitly (NOT the default domain
	// resolver, which points at a CN-local resolver) so the lookup detours
	// client→hub→exit→1.1.1.1 and Cloudflare returns exit-local edges. resolve is
	// a non-final action, so matching continues to the QUIC reject / Final below.
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeResolve,
				ResolveOptions: option.RouteActionResolve{
					Server:     DNSRemoteTag,
					Strategy:   option.DomainStrategy(C.DomainStrategyIPv4Only),
					RewriteTTL: &REMOTE_DNS_TTL,
				},
			},
		},
	})
	// Suppress tunnelled HTTP/3. Tunnelled QUIC (UDP/443) degrades badly over the
	// REALITY-VISION-over-TCP leg (userspace datagram framing + double loss recovery across
	// the long RTT), so reject it and let apps fall back to HTTP/2 on TCP/443. This runs
	// AFTER the direct/.cn/private/Apple/regional rules above, so only traffic bound for the
	// tunnel (Final) is affected — direct destinations keep their native UDP/QUIC path, and
	// non-443 UDP (WebRTC, VoIP, games, DoQ) plus UDP/53 (hijacked earlier) are untouched.
	// method=default returns ICMP unreachable → QUIC stacks fall back immediately; no_drop
	// prevents sing-box downgrading to a silent drop under the cold-start QUIC burst
	// (>50 rejects/30s), which is exactly when fast fallback matters. Gated by the
	// (overridable) block-quic option so the backend can revert without a client rebuild.
	if hopt.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Network: badoption.Listable[string]{"udp"},
					Port:    badoption.Listable[uint16]{443},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
						NoDrop: true,
					},
				},
			},
		})
	}
	options.Route = &option.RouteOptions{
		Rules:               routeRules,
		Final:               OutboundMainDetour,
		AutoDetectInterface: (!C.IsAndroid && !C.IsIos) && (hopt.EnableTun || hopt.EnableTunService),
		// default_domain_resolver must resolve without the tunnel — it is what
		// resolves outbound server addresses in the first place. That rules out
		// dns-remote by construction, and inside the GFW every direct-path
		// resolver is either poisoned or PRC-operated.
		//
		// DO NOT switch to local/system DNS (dns-local): that is the CN ISP
		// resolver, which poisons foreign domains and would corrupt any stray
		// foreign-hostname lookup this catch-all handles.
		//
		// dns-trick-direct (fragmented DoH to Cloudflare) was considered and
		// rejected: it still bootstraps via alidns, and fragmentation can fail
		// with no fallback path for this setting.
		//
		// Accepted tradeoff: doh.pub (Tencent) sees whatever reaches this
		// catch-all. Bounded by the MW invariant that hub addresses are always
		// IP literals, asserted in the transform — see Step 14.15.
		//
		// Note: this block is CN-targeted. For non-CN distribution a
		// region-conditional default is the eventual fix (deferred; see
		// DECISION_default_domain_resolver.md).
		DefaultDomainResolver: &option.DomainResolveOptions{
			Server:   DNSCNDirectTag,
		},
		// OverrideAndroidVPN: hopt.EnableTun && C.IsAndroid,
		RuleSet:     rulesets,
		FindProcess: false,
		// GeoIP: &option.GeoIPOptions{
		// 	Path: opt.GeoIPPath,
		// },
		// Geosite: &option.GeositeOptions{
		// 	Path: opt.GeoSitePath,
		// },
	}
	// HTTP/3 discovery suppression (companion to the UDP/443 route reject above): answer
	// HTTPS/SVCB (type 65/64) queries with NOERROR + empty answer (NODATA), so cold clients
	// never learn h3 is available and go straight to HTTP/2 without a failed QUIC attempt.
	// Placed AFTER the direct/.cn DNS rules (which carry no query_type and so still resolve
	// HTTPS/SVCB for direct destinations, preserving their native h3) and BEFORE the fakeip
	// A/AAAA catch-all and the remote catch-all — so only tunnelled names are suppressed.
	// NODATA (not NXDOMAIN, not REFUSED) is the correct, cacheable negative answer.
	if hopt.BlockQuic {
		noErrRcode := option.DNSRCode(sdns.RcodeSuccess)
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				QueryType: badoption.Listable[option.DNSQueryType]{
					option.DNSQueryType(mDNS.StringToType["HTTPS"]),
					option.DNSQueryType(mDNS.StringToType["SVCB"]),
				},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypePredefined,
				PredefinedOptions: option.DNSRouteActionPredefined{
					Rcode: &noErrRcode,
				},
			},
		})
	}
	// FakeIP catch-all removed. A/AAAA queries for tunnelled names fall through to
	// the terminal remote rule below, which resolves them for real over the
	// tunnel (dns-remote → hub → exit), so the hub receives IPs, not names.

	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:   DNSMultiRemoteTag,
				// Short TTL: this is the remote-resolution catch-all that now
				// caches real CDN addresses (see REMOTE_DNS_TTL in dns.go).
				RewriteTTL:     &REMOTE_DNS_TTL,
				BypassIfFailed: false,
			},
		},
	},
	)
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSRemoteTagFallback,
	// 			Strategy:       hopt.RemoteDnsDomainStrategy,
	// 			RewriteTTL:     &DEFAULT_DNS_TTL,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	// dnsRules = append(dnsRules, option.DefaultDNSRule{

	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSTricksDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server: DNSLocalTag,
	// 			// BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	for _, dnsRule := range dnsRules {
		if dnsRule.IsValid() {
			options.DNS.Rules = append(
				options.DNS.Rules,
				option.DNSRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: dnsRule,
				},
			)
		}
	}
	// }
	return nil
}

func patchHiddifyWarpFromConfig(out *option.Outbound, opt HiddifyOptions) *option.Outbound {
	if out.Type == C.TypePsiphon {
		return out
	}
	if opt.Warp.EnableWarp && opt.Warp.Mode == "proxy_over_warp" {
		if opts, ok := out.Options.(option.DialerOptionsWrapper); ok {
			dialer := opts.TakeDialerOptions()
			dialer.Detour = WARPConfigTag
			opts.ReplaceDialerOptions(dialer)
		}
	}
	return out
}

var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateRandomString(length int) string {
	// Determine the number of bytes needed
	bytesNeeded := (length*6 + 7) / 8

	// Generate random bytes
	randomBytes := make([]byte, bytesNeeded)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "hiddify"
	}

	// Encode random bytes to base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim padding characters and return the string
	return randomString[:length]
}
