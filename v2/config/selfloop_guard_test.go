package config

import (
	"runtime"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// findRule returns the index of the first rule satisfying match, or -1.
func findRule(rules []option.Rule, match func(option.Rule) bool) int {
	for i, rule := range rules {
		if match(rule) {
			return i
		}
	}
	return -1
}

func routesTo(rule option.Rule, outbound string) bool {
	switch rule.Type {
	case C.RuleTypeDefault:
		return rule.DefaultOptions.RouteOptions.Outbound == outbound
	case C.RuleTypeLogical:
		return rule.LogicalOptions.RouteOptions.Outbound == outbound
	}
	return false
}

// The self-loop guard must refuse IPv4 entering the tun from anything but the
// tun itself, and it must do so before any rule can route such a packet onward.
//
// What it defends: a Windows Mobile Hotspot causes the host to re-inject our own
// outbound dials into our own tun, carrying the host's physical source address.
// Whatever rule matches next re-dials the same destination, and the loop consumes
// a goroutine and a socket per turn until the Go runtime cannot allocate another
// OS thread. Ordering is the whole defence -- a guard placed after the CN-direct
// rules would never see the packets that matter.
func TestSelfLoopGuard(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	rules := built.Route.Rules

	guardAt := findRule(rules, func(r option.Rule) bool {
		return r.Type == C.RuleTypeLogical && r.LogicalOptions.Action == C.RuleActionTypeReject
	})

	// Windows-only by design: the loop was only ever reproduced there, and the
	// rule refuses traffic a Linux host might be forwarding on purpose. Asserted
	// in both directions so neither the gate nor its absence can drift silently.
	if !C.IsWindows {
		if guardAt != -1 {
			t.Errorf("guard present at rule %d on %s; it is scoped to Windows", guardAt, runtime.GOOS)
		}
		t.Skipf("guard is Windows-only; nothing to assert on %s", runtime.GOOS)
	}
	if guardAt == -1 {
		t.Fatal("no logical reject rule in the built config; the self-loop guard is missing")
	}

	t.Run("sits immediately after hijack-dns", func(t *testing.T) {
		hijackAt := findRule(rules, func(r option.Rule) bool {
			return r.DefaultOptions.Action == C.RuleActionTypeHijackDNS
		})
		if hijackAt == -1 {
			t.Fatal("no hijack-dns rule")
		}
		if guardAt != hijackAt+1 {
			t.Errorf("guard at %d, hijack-dns at %d; want the guard directly after it", guardAt, hijackAt)
		}
	})

	// The real invariant. `direct` re-dials whatever was just captured, which is
	// how the loop sustains itself, so the guard is only effective while it runs
	// first.
	t.Run("precedes every rule that routes to direct", func(t *testing.T) {
		for i, rule := range rules {
			if i > guardAt {
				break
			}
			if routesTo(rule, OutboundDirectTag) || routesTo(rule, OutboundDirectFragmentTag) {
				t.Errorf("rule %d routes to direct before the guard at %d", i, guardAt)
			}
		}
	})

	t.Run("matches tun inbound, IPv4 only, source not the tun", func(t *testing.T) {
		sub := built.Route.Rules[guardAt].LogicalOptions.Rules
		if got := built.Route.Rules[guardAt].LogicalOptions.Mode; got != C.LogicalTypeAnd {
			t.Errorf("mode = %q, want %q", got, C.LogicalTypeAnd)
		}
		if len(sub) != 3 {
			t.Fatalf("got %d sub-rules, want 3 (inbound, ip_version, source)", len(sub))
		}

		if got := sub[0].DefaultOptions.Inbound; len(got) != 1 || got[0] != InboundTUNTag {
			t.Errorf("inbound = %v, want [%s]", got, InboundTUNTag)
		}

		// IPv4 only, and this is not incidental: the tun's IPv6 is a ULA, so
		// source selection hands real IPv6 traffic the host's GLOBAL address.
		// A family-agnostic guard would reject ordinary IPv6 connections.
		if got := sub[1].DefaultOptions.IPVersion; got != 4 {
			t.Errorf("ip_version = %d, want 4 -- a family-agnostic guard rejects legitimate IPv6", got)
		}

		src := sub[2].DefaultOptions
		if !src.Invert {
			t.Error("source rule is not inverted; this would reject the tun's own traffic and nothing else")
		}
		if len(src.SourceIPCIDR) != 1 || src.SourceIPCIDR[0] != TunAddress4 {
			t.Errorf("source_ip_cidr = %v, want [%s]", src.SourceIPCIDR, TunAddress4)
		}
	})

	// A silent drop leaves our own captured dial occupying a socket for the full
	// dial timeout; the pile-up is what exhausted the thread pool.
	t.Run("rejects with RST rather than dropping", func(t *testing.T) {
		if got := built.Route.Rules[guardAt].LogicalOptions.RejectOptions.Method; got != C.RuleActionRejectMethodDefault {
			t.Errorf("reject method = %q, want %q", got, C.RuleActionRejectMethodDefault)
		}
	})
}

// The guard's allowed source and the tun's assigned address are the same value.
// Were they to drift, the guard would reject every packet the tunnel carries.
func TestSelfLoopGuardUsesTheTunsOwnAddress(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	var tunAddrs []string
	for _, in := range built.Inbounds {
		if in.Type != C.TypeTun {
			continue
		}
		for _, prefix := range in.Options.(*option.TunInboundOptions).Address {
			tunAddrs = append(tunAddrs, prefix.String())
		}
	}
	if len(tunAddrs) == 0 {
		t.Fatal("no tun inbound in the built config")
	}

	found := false
	for _, addr := range tunAddrs {
		if addr == TunAddress4 {
			found = true
		}
	}
	if !found {
		t.Errorf("tun addresses %v do not include the guard's allowed source %s", tunAddrs, TunAddress4)
	}
}
