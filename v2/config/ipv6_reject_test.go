package config

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func isTunnelIPv6Refusal(rule option.Rule) bool {
	if rule.Type != C.RuleTypeLogical || rule.LogicalOptions.Action != C.RuleActionTypeReject {
		return false
	}
	for _, sub := range rule.LogicalOptions.Rules {
		if sub.DefaultOptions.IPVersion == 6 {
			return true
		}
	}
	return false
}

// Tunnel-bound IPv6 must be refused while the app is still connecting, so its
// Happy Eyeballs falls back to IPv4. The exits carry no IPv6; refused anywhere
// later -- at the hub, or by a reject further down this list -- the app has
// already seen IPv6 connect and keeps retrying the dead address.
//
// Position is the whole mechanism: sing-box's pre-handshake match stops at the
// first sniff action, so only rules ahead of it can refuse a connection before
// the app's handshake completes.
func TestTunnelIPv6RefusedBeforeSniff(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts func() *HiddifyOptions
	}{
		{"shipped", func() *HiddifyOptions { o := DefaultHiddifyOptions(); shipped(o); return o }},
		{"go-defaults", DefaultHiddifyOptions},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built, err := BuildConfig(t.Context(), tc.opts(), &ReadOptions{Options: outbounds(2)})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			rules := built.Route.Rules

			at := findRule(rules, isTunnelIPv6Refusal)
			if at == -1 {
				t.Fatal("no tunnel IPv6 refusal in the built config")
			}

			t.Run("is the first route rule, ahead of every sniff", func(t *testing.T) {
				if at != 0 {
					t.Errorf("refusal at rule %d, want 0", at)
				}
				sniffAt := findRule(rules, func(r option.Rule) bool {
					return r.DefaultOptions.Action == C.RuleActionTypeSniff ||
						r.LogicalOptions.Action == C.RuleActionTypeSniff
				})
				if sniffAt != -1 && sniffAt < at {
					t.Errorf("sniff at %d precedes the refusal at %d; the refusal would fire after the handshake", sniffAt, at)
				}
			})

			rule := rules[at].LogicalOptions
			t.Run("matches tun IPv6, sparing private, direct IPs and DNS", func(t *testing.T) {
				if rule.Mode != C.LogicalTypeAnd || rule.Invert {
					t.Fatalf("mode = %q, invert = %v; want a plain AND", rule.Mode, rule.Invert)
				}
				if len(rule.Rules) != 5 {
					t.Fatalf("got %d sub-rules, want 5 (inbound, ip_version, private, direct IPs, port)", len(rule.Rules))
				}
				sub := func(i int) option.RawDefaultRule { return rule.Rules[i].DefaultOptions.RawDefaultRule }

				if got := sub(0).Inbound; len(got) != 1 || got[0] != InboundTUNTag || sub(0).Invert {
					t.Errorf("sub-rule 0 = inbound %v (invert %v), want [%s]", got, sub(0).Invert, InboundTUNTag)
				}
				if got := sub(1).IPVersion; got != 6 || sub(1).Invert {
					t.Errorf("sub-rule 1 = ip_version %d (invert %v), want 6", got, sub(1).Invert)
				}
				// Spares the tun's own IPv6 DNS address (a ULA) and link-local
				// neighbours, none of which an exit could reach anyway.
				if !sub(2).IPIsPrivate || !sub(2).Invert {
					t.Errorf("sub-rule 2 = ip_is_private %v (invert %v), want an inverted ip_is_private", sub(2).IPIsPrivate, sub(2).Invert)
				}
				// Spares IPv6 the CN-direct rule sends out directly, as before.
				if got := sub(3).RuleSet; len(got) != 1 || got[0] != "direct-regional-ips" || !sub(3).Invert {
					t.Errorf("sub-rule 3 = rule_set %v (invert %v), want inverted [direct-regional-ips]", got, sub(3).Invert)
				}
				// Spares DNS carried over IPv6, so it still reaches hijack-dns.
				if got := sub(4).Port; len(got) != 1 || got[0] != 53 || !sub(4).Invert {
					t.Errorf("sub-rule 4 = port %v (invert %v), want inverted [53]", got, sub(4).Invert)
				}
			})

			// A silent drop leaves the app waiting out its connect timeout -- the
			// hang the rule exists to remove.
			t.Run("refuses with a reset", func(t *testing.T) {
				if got := rule.RejectOptions.Method; got != C.RuleActionRejectMethodDefault {
					t.Errorf("reject method = %q, want %q", got, C.RuleActionRejectMethodDefault)
				}
			})

			// The spared set must exist, or the box refuses to start, and IPv6 it
			// spares must still have a direct route to fall through to.
			t.Run("spared rule-set is defined and routed direct", func(t *testing.T) {
				defined := false
				for _, rs := range built.Route.RuleSet {
					if rs.Tag == "direct-regional-ips" {
						defined = true
					}
				}
				if !defined {
					t.Fatal("direct-regional-ips is not defined in the built config")
				}
				routed := findRule(rules[at+1:], func(r option.Rule) bool {
					if !routesTo(r, OutboundDirectTag) {
						return false
					}
					for _, s := range append([]option.Rule{r}, r.LogicalOptions.Rules...) {
						for _, tag := range s.DefaultOptions.RuleSet {
							if tag == "direct-regional-ips" && !s.DefaultOptions.Invert {
								return true
							}
						}
					}
					return false
				})
				if routed == -1 {
					t.Error("no later rule routes direct-regional-ips to direct; spared IPv6 would reach the tunnel")
				}
			})
		})
	}
}

// ruleSetRouter is just enough of a router for sing-box rules to find their
// rule-sets; anything else a rule asked of it would panic, which is the point.
type ruleSetRouter struct {
	adapter.Router
	sets map[string]adapter.RuleSet
}

func (r ruleSetRouter) RuleSet(tag string) (adapter.RuleSet, bool) {
	set, ok := r.sets[tag]
	return set, ok
}

// What the refusal actually refuses, decided by sing-box's own matcher against
// the bundled direct-regional-ips -- the shape test above cannot tell a rule
// that refuses the wrong traffic from one that refuses the right traffic.
func TestTunnelIPv6RefusalMatches(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)
	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	at := findRule(built.Route.Rules, isTunnelIPv6Refusal)
	if at == -1 {
		t.Fatal("no tunnel IPv6 refusal in the built config")
	}

	logger := log.NewNOPFactory().Logger()
	directIPs, err := rule.NewRuleSet(t.Context(), logger, option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          "direct-regional-ips",
		Format:       C.RuleSetFormatBinary,
		LocalOptions: option.LocalRuleSet{Path: filepath.Join(ruleSetGuardDir(t), "direct-regional-ips.srs")},
	})
	if err != nil {
		t.Fatalf("load direct-regional-ips: %v", err)
	}
	t.Cleanup(func() { _ = directIPs.Close() })

	ctx := service.ContextWith[adapter.Router](t.Context(), ruleSetRouter{
		sets: map[string]adapter.RuleSet{"direct-regional-ips": directIPs},
	})
	refusal, err := rule.NewRule(ctx, logger, built.Route.Rules[at], false)
	if err != nil {
		t.Fatalf("sing-box refuses the rule: %v", err)
	}
	if err := refusal.Start(); err != nil {
		t.Fatalf("start the rule: %v", err)
	}
	t.Cleanup(func() { _ = refusal.Close() })

	for _, tc := range []struct {
		name    string
		inbound string
		network string
		dest    string
		refused bool
	}{
		{"the poisoned sentinel", InboundTUNTag, N.NetworkTCP, "[2001::1]:443", true},
		{"public IPv6 over UDP", InboundTUNTag, N.NetworkUDP, "[2606:4700:4700::1111]:443", true},
		{"IPv4", InboundTUNTag, N.NetworkTCP, "1.1.1.1:443", false},
		{"the tun's own IPv6 DNS address", InboundTUNTag, N.NetworkUDP, "[fdfe:dcba:9876::2]:53", false},
		{"a unique local address", InboundTUNTag, N.NetworkTCP, "[fd00::1]:443", false},
		{"a link-local neighbour", InboundTUNTag, N.NetworkUDP, "[fe80::1]:5353", false},
		{"IPv6 in direct-regional-ips", InboundTUNTag, N.NetworkTCP, "[240e:312::1]:443", false},
		{"DNS to a public IPv6 resolver", InboundTUNTag, N.NetworkUDP, "[2606:4700:4700::1111]:53", false},
		{"IPv6 not from the tun", InboundMixedTag, N.NetworkTCP, "[2001::1]:443", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := M.ParseSocksaddr(tc.dest)
			metadata := adapter.InboundContext{
				Inbound:     tc.inbound,
				Network:     tc.network,
				Destination: dest,
			}
			if tc.inbound == InboundTUNTag {
				// The tun stamps the packet's family; other inbounds leave it 0.
				metadata.IPVersion = 4
				if dest.Addr.Is6() {
					metadata.IPVersion = 6
				}
			}
			if got := refusal.Match(&metadata); got != tc.refused {
				t.Errorf("%s %s from %s: refused = %v, want %v", tc.network, tc.dest, tc.inbound, got, tc.refused)
			}
		})
	}
}
