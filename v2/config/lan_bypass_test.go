package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func isLANBypass(rule option.Rule) bool {
	if rule.Type != C.RuleTypeLogical || rule.LogicalOptions.RouteOptions.Outbound != OutboundDirectTag {
		return false
	}
	for _, sub := range rule.LogicalOptions.Rules {
		if sub.DefaultOptions.IPIsPrivate {
			return true
		}
	}
	return false
}

// Local-network destinations must leave directly. No bundled rule-set holds a
// private range -- direct-private is a list of local NAMES -- so without the
// LAN rule they fell through to the tunnel and the hub dropped them: all of the
// LAN on Android, and every private range off the local subnet on Windows.
func TestLANDestinationsGoDirect(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)
	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	p := newRoutingProbe(t, built)

	for _, tc := range []struct {
		name     string
		network  string
		dest     string
		protocol string
		want     string
	}{
		{"a LAN device over TCP", N.NetworkTCP, "192.168.31.150:8009", "", OutboundDirectTag},
		{"a LAN device over UDP", N.NetworkUDP, "192.168.31.150:54178", "", OutboundDirectTag},
		{"the router's admin page", N.NetworkTCP, "192.168.31.1:80", C.ProtocolHTTP, OutboundDirectTag},
		{"an ISP modem behind the router", N.NetworkTCP, "192.168.1.1:443", C.ProtocolTLS, OutboundDirectTag},
		{"10/8", N.NetworkTCP, "10.0.0.5:445", "", OutboundDirectTag},
		{"172.16/12", N.NetworkTCP, "172.20.1.1:443", C.ProtocolTLS, OutboundDirectTag},
		{"SSDP multicast", N.NetworkUDP, "239.255.255.250:1900", "", OutboundDirectTag},
		{"IPv6 link-local", N.NetworkTCP, "[fe80::1]:80", "", OutboundDirectTag},
		{"IPv6 unique local", N.NetworkTCP, "[fd00::1]:80", "", OutboundDirectTag},
		// DNS sent to the router stays with our resolver, as before.
		{"DNS to the router", N.NetworkUDP, "192.168.31.1:53", C.ProtocolDNS, "hijack-dns"},
		// Carved out: never dial the tun's own addresses out of the adapter.
		{"the tun's own IPv4 subnet", N.NetworkTCP, "172.19.0.2:80", "", p.routeFinal},
		{"the tun's own IPv6 subnet", N.NetworkTCP, "[fdfe:dcba:9876::2]:80", "", p.routeFinal},
		// Unchanged.
		{"a public address", N.NetworkTCP, "8.8.8.8:443", C.ProtocolTLS, p.routeFinal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.routeOf(fromTun(tc.network, tc.dest, tc.protocol)); got != tc.want {
				t.Errorf("%s %s routed to %q, want %q", tc.network, tc.dest, got, tc.want)
			}
		})
	}
}

// The rule has to sit after hijack-dns (and, on Windows, the self-loop guard),
// and the private check must never move into a DNS rule: an address condition
// there makes sing-box resolve every query just to test it.
func TestLANBypassPlacement(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)
	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	rules := built.Route.Rules

	at := findRule(rules, isLANBypass)
	if at == -1 {
		t.Fatal("no LAN bypass rule in the built config")
	}
	hijackAt := findRule(rules, func(r option.Rule) bool { return r.DefaultOptions.Action == C.RuleActionTypeHijackDNS })
	if hijackAt == -1 || at < hijackAt {
		t.Errorf("LAN rule at %d, hijack-dns at %d; DNS to a LAN address would leave unanswered by us", at, hijackAt)
	}
	if guardAt := findRule(rules, isSelfLoopGuard); guardAt != -1 && at < guardAt {
		t.Errorf("LAN rule at %d precedes the self-loop guard at %d", at, guardAt)
	}
	if got := rules[at].LogicalOptions.Mode; got != C.LogicalTypeAnd || rules[at].LogicalOptions.Invert {
		t.Errorf("mode %q invert %v, want a plain AND", got, rules[at].LogicalOptions.Invert)
	}

	for i, r := range built.DNS.Rules {
		if r.DefaultOptions.IPIsPrivate {
			t.Errorf("DNS rule %d tests ip_is_private; keep address checks out of DNS rules", i)
		}
	}
}

// The option no longer switches the rule: an old client sending either value
// gets the same config.
func TestLANBypassIgnoresTheOldOption(t *testing.T) {
	for _, value := range []bool{false, true} {
		opts := DefaultHiddifyOptions()
		shipped(opts)
		opts.BypassLAN = value
		built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		count := 0
		for _, r := range built.Route.Rules {
			if isLANBypass(r) || r.DefaultOptions.IPIsPrivate {
				count++
			}
		}
		if count != 1 {
			t.Errorf("bypass-lan=%v: %d private-address rules, want exactly 1", value, count)
		}
	}
}
