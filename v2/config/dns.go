package config

import (
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	// dnscode "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

var DnsDirectTags = []string{
	DNSStaticTag,
	DNSDirectTag,
	DNSLocalTag,
}
var DnsRemoteTags = []string{
	DNSRemoteTag,
	DNSRemoteTagFallback,
	DNSTricksDirectTag,
}

// dropEmptyDirectDetour blanks a detour that names an outbound carrying no dial
// options.
//
// sing-box 1.14 refuses to start any transport whose detour resolves to an
// option-less direct outbound ("detour to an empty direct outbound makes no
// sense", common/dialer/detour.go), and both of ours are exactly that:
// `direct §hide§` has always been `&option.DirectOutboundOptions{}`, and
// `direct-fragment §hide§` became one when 1.14 moved TLSFragment out of
// DialerOptions. Blanking is behaviour-preserving — see the long note on
// direct_detour below.
//
// This is a function rather than four literals because the WARP detour is
// decided at build time: with WARP enabled it names a real endpoint and must be
// left alone, and only its disabled fallback lands on direct-fragment.
func dropEmptyDirectDetour(detour string) string {
	switch detour {
	case OutboundDirectTag, OutboundDirectFragmentTag:
		return ""
	}
	return detour
}

var DEFAULT_DNS_TTL = uint32(60 * 60 * 24)

// TTL for rules that resolve REMOTELY (over the tunnel). Kept short: now that
// FakeIP is gone these cache real CDN addresses, and Fastly/Cloudflare/Google
// rotate edges continuously — a day-long pin turns a rotated edge into a black
// hole. The stable .cn/direct-* rules keep DEFAULT_DNS_TTL (those queries are
// cheap and the answers don't move).
var REMOTE_DNS_TTL = uint32(60 * 60)

func getDnsAddress(d string) string {
	if !strings.Contains(d, "://") {
		return "udp://" + d
	}
	return d
}

func setDns(options *option.Options, opt *HiddifyOptions, staticIps *map[string][]string) error {
	remoteAddr := getDnsAddress(opt.RemoteDnsAddress)
	fallbackAddr := "https://8.8.8.8/dns-query"
	if remoteAddr == fallbackAddr {
		fallbackAddr = "https://1.0.0.1/dns-query"
	}

	// if strings.HasPrefix(remoteAddr, "udp://") {
	// 	remoteAddr = strings.Replace(remoteAddr, "udp://", "tcp://", 1)
	// }

	remote_dns, err := getDNSServerOptions(DNSRemoteTag, remoteAddr, DNSDirectTag, OutboundMainDetour)
	if err != nil {
		return err
	}
	remote_dns_fallback, err := getDNSServerOptions(DNSRemoteTagFallback, fallbackAddr, DNSDirectTag, OutboundMainDetour)
	if err != nil {
		return err
	}
	remote_no_warp_dns, err := getDNSServerOptions(DNSRemoteNoWarpTag, opt.RemoteDnsAddress, DNSDirectTag, dropEmptyDirectDetour(OutboundWARPConfigDetour))
	if err != nil {
		return err
	}

	// Direct DNS dials direct (no TLS fragmentation). The fragmented outbound
	// was useful upstream for DPI evasion against the user's local ISP, but
	// this build only targets CN networks: the direct DNS endpoint is an
	// in-CN DoH server (alidns/doh.pub) where fragmentation adds latency and
	// risks CDN-edge confusion without any evasion benefit.
	//
	// The detour is EMPTY, not OutboundDirectTag, and that is load-bearing.
	//
	// sing-box 1.14 rejects a detour pointing at a direct outbound that carries
	// no dial options — "detour to an empty direct outbound makes no sense"
	// (common/dialer/detour.go). Our `direct §hide§` is exactly that:
	// `&option.DirectOutboundOptions{}`. The check runs when the transport's
	// dialer is initialised, i.e. in Start, NOT in box.New — which is why
	// libbox.CheckConfigOptions accepted this config while the shipped core
	// could not bring a tunnel up. See TestRealProfileStartsTheBox.
	//
	// Dropping the detour is behaviour-preserving, not a workaround. With no
	// detour and DefaultOutbound unset (dns/transport_dialer.go never sets it),
	// dialer.NewWithOptions falls through to NewDefault — a plain direct system
	// dial. That is precisely what detouring to an option-less direct outbound
	// did. Domain resolution is unaffected: it is driven by DomainResolver
	// (the third argument here), which is set either way.
	//
	// Do NOT "fix" this by pointing the detour at the proxy: these servers exist
	// specifically to resolve CN destinations off-tunnel.
	direct_detour := ""

	direct_dns, err := getDNSServerOptions(DNSDirectTag, opt.DirectDnsAddress, DNSLocalTag, direct_detour)
	if err != nil {
		return err
	}
	// CN-reachable DoH for the China-direct rule-set. Resolves doh.pub via the
	// static-IP server (seeded in builder.go) and dials direct without TLS
	// fragmentation — the endpoint is inside the GFW and fragmentation is both
	// unnecessary and a likely CDN-edge irritant here.
	cn_direct_dns, err := getDNSServerOptions(DNSCNDirectTag, "https://doh.pub/dns-query", DNSStaticTag, direct_detour)
	if err != nil {
		return err
	}
	// Independent CN-reachable fallback (Alibaba) for the China-direct path.
	// Queried only when doh.pub fails (the CN-direct DNS rules chain
	// primary→fallback via BypassIfFailed), so a single-provider outage no
	// longer silently degrades CN routing to the proxy resolver. Bootstrapped
	// via the same static-IP server; dials direct without fragmentation.
	cn_direct_dns_fallback, err := getDNSServerOptions(DNSCNDirectTagFallback, "https://dns.alidns.com/dns-query", DNSStaticTag, direct_detour)
	if err != nil {
		return err
	}
	// Also detour-less, for the same reason — but by a different route: this
	// one's target, `direct-fragment §hide§`, only BECAME an empty direct
	// outbound during the sing-box 1.14 bump. 1.14 removed TLSFragment from
	// DialerOptions (fragmentation is now a TLS option and a route rule action),
	// so builder.go's TLSFragment{Enabled: true, ...} block had to go, and what
	// remained had no dial options at all.
	//
	// This server still fragments. The "#fragment=300" in its URL sets
	// fragmentation on the DNS server's own TLS options, which is independent of
	// the dialer and survives untouched — the golden pins it as
	// tls.fragment=true, fragment_fallback_delay=300ms. What was lost is the
	// dialer-level fragmentation the `direct-fragment §hide§` outbound applied to
	// anything routed THROUGH it, and its only users were this detour and WARP
	// (removed). No live consumer, so this is recorded, not repaired.
	trick_dns, err := getDNSServerOptions(DNSTricksDirectTag, "https://dns.cloudflare.com/dns-query#fragment=300", DNSDirectTag, direct_detour)
	if err != nil {
		return err
	}
	local_dns, err := getDNSServerOptions(DNSLocalTag, "local", "", "")
	if err != nil {
		return err
	}
	static_dns, err := getStaticDNSServerOptions(DNSStaticTag, staticIps)
	if err != nil {
		return err
	}
	// block_dns, err := getDNSServerOptions(DNSBlockTag, "rcode://name_error", "", "")
	// if err != nil {
	// 	return err
	// }

	// multi_dns_direct, err := getMultiDnsServerOptions(DNSMultiDirectTag, DnsDirectTags, false)
	// if err != nil {
	// 	return err
	// }

	// multi_dns_remote, err := getMultiDnsServerOptions(DNSMultiRemoteTag, DnsRemoteTags, true)
	// if err != nil {
	// 	return err
	// }

	dnsOptions := option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			DNSClientOptions: option.DNSClientOptions{
				// Global replacement for the per-rule `strategy` that sing-box 1.14
				// deprecated on DNS rule ACTIONS. Every rule here carried the same
				// value, so hoisting it is an exact translation -- see the comment
				// above dnsRules in builder.go for why it had to move at all.
				Strategy:         opt.DirectDnsDomainStrategy,
				IndependentCache: opt.IndependentDNSCache && !C.IsIos,
				// Expiry MUST stay on. While FakeIP was enabled the cached entries
				// were synthetic so pinning them was harmless; now that real CDN
				// addresses are cached, disabling expiry would pin them for the
				// life of the process.
				DisableExpire: false,
			},
			Final: DNSMultiRemoteTag,

			Servers: []option.DNSServerOptions{
				*static_dns,
				*remote_dns,
				*remote_dns_fallback,
				*trick_dns,
				*direct_dns,
				*cn_direct_dns,
				*cn_direct_dns_fallback,
				*local_dns,
				*remote_no_warp_dns,
				// *multi_dns_direct,
				// *multi_dns_remote,
				// *block_dns,
			},
			Rules: []option.DNSRule{},
		},
	}
	// FakeIP intentionally NOT registered. The hub runs domainStrategy:AsIs and
	// needs real IP addresses; FakeIP would hand it synthetic 198.18.x.x that it
	// maps back to a domain, defeating exit-local CDN resolution. Real resolution
	// happens via the terminal dns-remote rule (builder.go) over the tunnel.
	options.DNS = &dnsOptions

	// options.DNS.StaticIPs["time.apple.com"] = []string{"time.g.aaplimg.com", "time.apple.com"}
	// options.DNS.StaticIPs["ipinfo.io"] = []string{"ipinfo.io"}
	// options.DNS.StaticIPs["dns.cloudflare.com"] = []string{"www.speedtest.net", "cloudflare.com"}
	// options.DNS.StaticIPs["ipwho.is"] = []string{"ipwho.is"}
	// options.DNS.StaticIPs["api.my-ip.io"] = []string{"api.my-ip.io"}
	// options.DNS.StaticIPs["myip.expert"] = []string{"myip.expert"}
	// options.DNS.StaticIPs["ip-api.com"] = []string{"ip-api.com"}
	// options.DNS.StaticIPs["freeipapi.com"] = []string{"www.speedtest.net", "cloudflare.com"}
	// options.DNS.StaticIPs["reallyfreegeoip.org"] = []string{"www.speedtest.net", "cloudflare.com"}
	// options.DNS.StaticIPs["ipapi.co"] = []string{"www.speedtest.net", "cloudflare.com"}
	// options.DNS.StaticIPs["api.ip.sb"] = []string{"www.speedtest.net", "cloudflare.com"}
	return nil
}
func getAllOutboundsOptions(options *option.Options) []any {
	outbounds := []any{}
	for _, o := range options.Outbounds {
		outbounds = append(outbounds, o.Options)
	}
	for _, o := range options.Endpoints {
		outbounds = append(outbounds, o.Options)
	}
	return outbounds
}
func addForceDirect(options *option.Options, hopt *HiddifyOptions) ([]option.DefaultDNSRule, error) {
	dnsMap := make(map[string]string)
	// outbounds := getAllOutboundsOptions(options)

	// for _, outbound := range outbounds {
	// 	// fmt.Println("out", outbound)
	// 	if server, ok := outbound.(option.ServerOptionsWrapper); ok {
	// 		serverDomain := server.TakeServerOptions().Server
	// 		detour := OutboundDirectTag
	// 		if dialer, ok := outbound.(option.DialerOptionsWrapper); ok {
	// 			if server_detour := dialer.TakeDialerOptions().Detour; server_detour != "" {
	// 				detour = server_detour
	// 			}
	// 		}
	// 		fmt.Println("serverDomain", serverDomain, "detour", detour)

	// 		if host, err := getHostnameIfNotIP(serverDomain); err == nil && host != "" {
	// 			fmt.Println("serverDomain", serverDomain, "host", host, "detour", detour)
	// 			if _, ok := dnsMap[host]; !ok || detour == OutboundDirectTag {
	// 				dnsMap[host] = detour
	// 			}
	// 		}
	// 	}
	// }

	// // dnsMap[]
	forceDirectRules := []option.DefaultDNSRule{}

	// Kill sing-box 1.14's IP-geolocation probes at the resolver.
	//
	// 1.14's outbound monitoring calls ipinfo.GetIpInfo for every outbound it
	// tests, which fans out to a dozen third-party endpoints — ip-api.com,
	// ipapi.co, ipinfo.io, ipwho.is, api.country.is, api.ip.sb, my-ip.io,
	// api.myip.com, cloudflare.com/cdn-cgi/trace, freeipapi.com, myip.expert,
	// reallyfreegeoip.org — one of them over plain HTTP. Each request shows a
	// third party the exit IP of one of our nodes. Nobody chose this; it arrived
	// with the engine bump, and it is exactly the kind of ambient outbound call
	// this product does not make.
	//
	// It cannot be switched off: option.MonitoringOptions has no flag for it, and
	// ipinfo's `providers`/`fallbackProviders` are unexported package vars, so
	// there is nothing to empty from here. Editing hiddify-sing-box is not an
	// option — that would mean maintaining a third fork.
	//
	// So it is stopped one layer down. Every provider is addressed by hostname
	// (none uses an IP literal, checked against the full provider list), so
	// refusing to resolve them makes GetIpInfo fail before a single packet
	// leaves. Monitoring treats the failure as "no IP info" and carries on: delay
	// measurement, group health and selection are unaffected. The cost is a
	// per-cycle WARN in the log, which is a fair price for the probe not
	// happening.
	//
	// GetAllIPCheckerDomainsDomains() covers `providers`. The two fallback-only
	// hosts are added by hand because that helper does not walk
	// fallbackProviders — check both lists if this ever looks incomplete.
	ipCheckerDomains := append([]string{}, ipinfo.GetAllIPCheckerDomainsDomains()...)
	ipCheckerDomains = append(ipCheckerDomains, "api.myip.com", "api.country.is")
	slices.Sort(ipCheckerDomains)
	ipCheckerDomains = slices.Compact(ipCheckerDomains)
	forceDirectRules = append(forceDirectRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{Domain: ipCheckerDomains},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeReject,
			RejectOptions: option.RejectActionOptions{
				Method: C.RuleActionRejectMethodDefault,
			},
		},
	})
	// if len(dnsMap) > 0 {
	// 	unique_dns_detours := make(map[string]bool)
	// 	for _, detour := range dnsMap {
	// 		unique_dns_detours[detour] = true
	// 	}

	// 	for detour := range unique_dns_detours {
	// 		domains := []string{}
	// 		for domain, d := range dnsMap {
	// 			if d == detour {
	// 				domains = append(domains, domain)
	// 			}
	// 		}
	// 		if len(domains) == 0 {
	// 			continue
	// 		}
	// 		dns_detour := DNSMultiDirectTag
	// 		if detour != OutboundDirectTag {
	// 			dns_detour = "dns-" + detour
	// 			remote_dns, err := getDNSServerOptions(dns_detour, hopt.RemoteDnsAddress, DNSDirectTag, detour)
	// 			if err != nil {
	// 				return nil, err
	// 			}
	// 			options.DNS.Servers = append(options.DNS.Servers, *remote_dns)

	// 		}

	// 		forceDirectRules = append(forceDirectRules,
	// 			option.DefaultDNSRule{
	// 				RawDefaultDNSRule: option.RawDefaultDNSRule{
	// 					Domain: domains,
	// 				},
	// 				DNSRuleAction: option.DNSRuleAction{
	// 					Action: C.RuleActionTypeRoute,
	// 					RouteOptions: option.DNSRouteActionOptions{
	// 						Server:         dns_detour,
	// 						BypassIfFailed: false,
	// 					},
	// 				},
	// 			},
	// 		)
	// 	}
	// }

	forceDirectRules = append(forceDirectRules,
		option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{
				Domain: []string{"api.cloudflareclient.com"},
			},
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         DNSRemoteNoWarpTag,
					BypassIfFailed: false,
					RewriteTTL:     &DEFAULT_DNS_TTL,
				},
			},
		},
	)

	dnsMap["api.cloudflareclient.com"] = ""
	for _, url := range hopt.ConnectionTestUrls { //To avoid dns bug when using urltest
		if host, err := getHostnameIfNotIP(url); err == nil {
			dnsMap[host] = ""
		}
	}
	// for _, d := range ipinfo.GetAllIPCheckerDomainsDomains() {
	// 	dnsMap[d] = ""
	// }
	domains := []string{}
	for domain := range dnsMap {
		domains = append(domains, domain)
	}
	// Go randomizes map iteration, so without this the rule's Domain list comes
	// out in a different order on every build and the generated config is not
	// reproducible. Routing is unaffected — a Domain list is a match set — but
	// non-reproducibility makes "did this change alter the config?" unanswerable,
	// which is the question the golden tests exist to answer.
	sort.Strings(domains)
	if len(domains) > 0 {
		// Connection-test URLs + cloudflareclient bootstrap. Resolve via the
		// CN-reachable DoH so URLTest probes don't trip over poisoned 1.1.1.1
		// answers for cp.cloudflare.com / google.com / etc. inside the GFW.
		forceDirectRules = append(forceDirectRules,
			option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					Domain: domains,
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server:         DNSCNDirectTag,
							RewriteTTL:     &DEFAULT_DNS_TTL,
						BypassIfFailed: true,
					},
				},
			},
		)
		// forceDirectRules = append(forceDirectRules,
		// 	option.DefaultDNSRule{
		// 		RawDefaultDNSRule: option.RawDefaultDNSRule{
		// 			Domain: domains,
		// 		},
		// 		DNSRuleAction: option.DNSRuleAction{
		// 			Action: C.RuleActionTypeRoute,
		// 			RouteOptions: option.DNSRouteActionOptions{
		// 				Server:         DNSTricksDirectTag,
		// 				Strategy:       hopt.DirectDnsDomainStrategy,
		// 				BypassIfFailed: false,
		// 			},
		// 		},
		// 	},
		// )
		// forceDirectRules = append(forceDirectRules,
		// 	option.DefaultDNSRule{
		// 		RawDefaultDNSRule: option.RawDefaultDNSRule{
		// 			Domain: domains,
		// 		},
		// 		DNSRuleAction: option.DNSRuleAction{
		// 			Action: C.RuleActionTypeRoute,
		// 			RouteOptions: option.DNSRouteActionOptions{
		// 				Server:         DNSLocalTag,
		// 				Strategy:       hopt.DirectDnsDomainStrategy,
		// 				BypassIfFailed: false,
		// 			},
		// 		},
		// 	},
		// )
	}
	return forceDirectRules, nil

}

func getDNSServerOptions(tag string, dnsurl string, domain_resolver string, detour string) (*option.DNSServerOptions, error) {
	serverURL, _ := url.Parse(dnsurl)
	var serverType string
	if serverURL != nil && serverURL.Scheme != "" {
		serverType = serverURL.Scheme
	} else {
		switch dnsurl {
		case "local", "fakeip":
			serverType = dnsurl
		default:
			serverType = C.DNSTypeUDP
		}
	}
	if res, _ := getHostnameIfNotIP(dnsurl); res == "" {
		domain_resolver = ""
	}
	remoteOptions := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
			DialerOptions: option.DialerOptions{
				Detour: detour,
				DomainResolver: &option.DomainResolveOptions{
					Server:   domain_resolver,
					Strategy: option.DomainStrategy(C.DomainStrategyPreferIPv4),
				},
			},
		},
	}
	o := option.DNSServerOptions{
		Tag: tag,
	}
	switch serverType {
	case C.DNSTypeLocal:
		o.Type = C.DNSTypeLocal
		o.Options = &option.LocalDNSServerOptions{
			RawLocalDNSServerOptions: remoteOptions.RawLocalDNSServerOptions,
			PreferGo:                 true,
		}
	case C.DNSTypeUDP:
		o.Type = C.DNSTypeUDP
		o.Options = &remoteOptions
		var serverAddr M.Socksaddr
		if serverURL == nil || serverURL.Scheme == "" {
			serverAddr = M.ParseSocksaddr(dnsurl)
		} else {
			serverAddr = M.ParseSocksaddr(serverURL.Host)
		}
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			remoteOptions.ServerPort = serverAddr.Port
		}
		remoteOptions.ConnectTimeout = badoption.Duration(5 * time.Second)
		remoteOptions.DisableTCPKeepAlive = true
	case C.DNSTypeTCP:
		o.Type = C.DNSTypeTCP
		o.Options = &remoteOptions
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			remoteOptions.ServerPort = serverAddr.Port
		}
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		o.Type = serverType
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 853 {
			remoteOptions.ServerPort = serverAddr.Port
		}
		o.Options = &option.RemoteTLSDNSServerOptions{
			RemoteDNSServerOptions: remoteOptions,
		}
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		o.Type = serverType
		httpsOptions := option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: remoteOptions,
			},
		}
		o.Options = &httpsOptions
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		serverAddr := M.ParseSocksaddr(serverURL.Host)
		if !serverAddr.IsValid() {
			return nil, E.New("invalid server address")
		}
		httpsOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 443 {
			httpsOptions.ServerPort = serverAddr.Port
		}
		if serverURL.Path != "/dns-query" {
			httpsOptions.Path = serverURL.Path
		}
		httpsOptions.TLS = &option.OutboundTLSOptions{
			Enabled: true,
		}
		if strings.Contains(dnsurl, "#fragment=") {

			httpsOptions.TLS.Fragment = true
			httpsOptions.TLS.RecordFragment = true

			splt := strings.Split(dnsurl, "#fragment=")
			data := splt[len(splt)-1]
			if delay, err := strconv.Atoi(data); err == nil && delay >= 0 {
				httpsOptions.TLS.FragmentFallbackDelay = badoption.Duration(time.Duration(delay) * time.Millisecond)
			} else {
				// httpsOptions.TLS.FragmentFallbackDelay = badoption.Duration(30 * time.Millisecond)
			}

		}
	// case "rcode":
	// 	var rcode int
	// 	if serverURL == nil {
	// 		return nil, E.New("invalid server address")
	// 	}
	// 	switch serverURL.Host {
	// 	case "success":
	// 		rcode = dnscode.RcodeSuccess
	// 	case "format_error":
	// 		rcode = dnscode.RcodeFormatError
	// 	case "server_failure":
	// 		rcode = dnscode.RcodeServerFailure
	// 	case "name_error":
	// 		rcode = dnscode.RcodeNameError
	// 	case "not_implemented":
	// 		rcode = dnscode.RcodeNotImplemented
	// 	case "refused":
	// 		rcode = dnscode.RcodeRefused
	// 	default:
	// 		return nil, E.New("unknown rcode: ", serverURL.Host)
	// 	}
	// 	o.Type = C.DNSTypeLegacyRcode
	// 	o.Options = rcode
	case C.DNSTypeDHCP:
		o.Type = C.DNSTypeDHCP
		dhcpOptions := option.DHCPDNSServerOptions{}
		if serverURL == nil {
			return nil, E.New("invalid server address")
		}
		if serverURL.Host != "" && serverURL.Host != "auto" {
			dhcpOptions.Interface = serverURL.Host
		}
		o.Options = &dhcpOptions
	case C.DNSTypeFakeIP:
		o.Type = C.DNSTypeFakeIP
		fakeipOptions := option.FakeIPDNSServerOptions{}
		// if legacyOptions, loaded := ctx.Value((*option.LegacyDNSFakeIPOptions)(nil)).(*option.LegacyDNSFakeIPOptions); loaded {
		// 	fakeipOptions.Inet4Range = legacyOptions.Inet4Range
		// 	fakeipOptions.Inet6Range = legacyOptions.Inet6Range
		// }
		o.Options = &fakeipOptions
	default:
		return nil, E.New("unsupported DNS server scheme: ", serverType)

	}
	return &o, nil
}

func getStaticDNSServerOptions(tag string, staticIps *map[string][]string) (*option.DNSServerOptions, error) {
	domain_ips := badjson.TypedMap[string, badoption.Listable[netip.Addr]]{}
	for domain, ips := range *staticIps {
		ipsConverted := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, err
			}
			ipsConverted = append(ipsConverted, addr)
		}
		domain_ips.Put(domain, ipsConverted)
	}
	o := option.DNSServerOptions{
		Tag:  tag,
		Type: C.DNSTypeHosts,
		Options: &option.HostsDNSServerOptions{
			Predefined: &domain_ips,
		},
	}
	return &o, nil
}
func getMultiDnsServerOptions(tag string, servers []string, parallel bool) (*option.DNSServerOptions, error) {
	o := option.DNSServerOptions{
		Tag:  tag,
		Type: C.DNSTypeMulti,
		Options: &option.MultiDNSServerOptions{
			Servers:  servers,
			Parallel: parallel,
			IgnoreRanges: []badoption.Prefix{
				badoption.Prefix(netip.MustParsePrefix("10.10.34.0/24")),
				badoption.Prefix(netip.MustParsePrefix("001:4188:2:600::/64")),
			},
		},
	}
	return &o, nil
}
