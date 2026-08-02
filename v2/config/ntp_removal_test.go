package config

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// buildTestConfig builds a config from the defaults with a couple of dummy
// outbounds, which is enough to exercise the DNS and route rule construction.
func buildTestConfig(t *testing.T) *option.Options {
	t.Helper()

	built, err := BuildConfig(context.Background(), DefaultHiddifyOptions(), &ReadOptions{
		Options: &option.Options{
			Outbounds: []option.Outbound{
				{Type: "direct", Tag: "node-a"},
				{Type: "direct", Tag: "node-b"},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	return built
}

// The NTP wiring (a setNTP helper, the enable-ntp option, and the forceDirectRoute
// DNS + route rules gated on it) was removed as dead code. It was dead because the
// call was commented out, so options.NTP was always nil and the rule list it fed was
// always empty. This asserts the resulting config is what that reasoning predicts —
// no NTP block — so a future change that reintroduces NTP has to reintroduce the
// direct-routing rules with it rather than silently sending time sync through the
// tunnel.
func TestBuiltConfigHasNoNTPBlock(t *testing.T) {
	if got := buildTestConfig(t).NTP; got != nil {
		t.Errorf("options.NTP = %+v, want nil", got)
	}
}

// The removed DNS rule was the only one that routed queries to `dns-direct`.
//
// This is the guard for a trap: it would be easy to read "nothing routes to
// dns-direct" as "dns-direct is dead" and delete the server. It is not dead — it is
// the domain_resolver for dns-trick-direct, and for dns-remote whenever
// remote-dns-address is overridden to a hostname instead of an IP literal. Deleting
// it would leave those pointing at a server that does not exist. Both halves are
// asserted together so the distinction cannot be lost.
func TestDNSDirectIsRegisteredButNotARoutingTarget(t *testing.T) {
	built := buildTestConfig(t)

	if built.DNS == nil {
		t.Fatal("built config has no DNS section")
	}

	registered := false
	for _, s := range built.DNS.Servers {
		if s.Tag == DNSDirectTag {
			registered = true
			break
		}
	}
	if !registered {
		t.Errorf("DNS server %q is not registered; dns-trick-direct and a hostname "+
			"remote-dns-address both reference it as their domain_resolver", DNSDirectTag)
	}

	for i, rule := range built.DNS.Rules {
		if rule.Type != "" && rule.Type != "default" {
			continue
		}
		if got := rule.DefaultOptions.DNSRuleAction.RouteOptions.Server; got == DNSDirectTag {
			t.Errorf("DNS rule %d routes queries to %q; the only rule that did so was the "+
				"NTP-gated one, which was removed as unreachable", i, got)
		}
	}
}
