package config

import (
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The default-interface choice must match sing-tun's, because the question is
// whether the adapter dials are actually bound to runs IPv6 — not whether any
// adapter does. The rows that matter are the ones where a different choice
// would answer differently.
func TestDefaultEgressMirrorsSingTun(t *testing.T) {
	ethernet := egressRoute{index: 9, alias: "Ethernet", up: true, metric: 25, ipv6Enabled: false}
	wifi := egressRoute{index: 12, alias: "Wi-Fi", up: true, metric: 35, ipv6Enabled: true}
	tun := egressRoute{index: 40, alias: "tun0", up: true, virtual: true, metric: 1, ipv6Enabled: true}
	down := egressRoute{index: 7, alias: "Ethernet 2", up: false, metric: 5, ipv6Enabled: true}

	cases := []struct {
		name      string
		routes    []egressRoute
		wantAlias string
		wantFound bool
	}{
		{"one adapter", []egressRoute{ethernet}, "Ethernet", true},
		{"lowest metric wins", []egressRoute{wifi, ethernet}, "Ethernet", true},
		{"our own tun is never the default", []egressRoute{tun, wifi}, "Wi-Fi", true},
		{"an adapter that is down is skipped", []egressRoute{down, wifi}, "Wi-Fi", true},
		{"first of equal metrics", []egressRoute{{alias: "A", up: true, metric: 10}, {alias: "B", up: true, metric: 10}}, "A", true},
		{"no default route", nil, "", false},
		{"only the tun", []egressRoute{tun}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := defaultEgress(tc.routes)
			if found != tc.wantFound || got.alias != tc.wantAlias {
				t.Errorf("defaultEgress = (%q, %v), want (%q, %v)", got.alias, found, tc.wantAlias, tc.wantFound)
			}
		})
	}
}

// The tun claims IPv6 only when the egress adapter runs it, and the local
// listener's IPv6 loopback does not follow: the two questions stay separate.
func TestTunClaimsIPv6OnlyWhenTheEgressAdapterRunsIt(t *testing.T) {
	if !isIPv6Supported() {
		t.Skip("this host has no IPv6 stack, so the tun never claims IPv6 here")
	}
	for _, egress := range []bool{false, true} {
		name := "egress without IPv6"
		if egress {
			name = "egress with IPv6"
		}
		t.Run(name, func(t *testing.T) {
			saved := probeEgressIPv6
			probeEgressIPv6 = func() bool { return egress }
			t.Cleanup(func() { probeEgressIPv6 = saved })

			built := mustBuildShipped(t, t.Context(), nil)
			var addrs []string
			for _, prefix := range tunOptions(t, built).Address {
				addrs = append(addrs, prefix.String())
			}
			if !slices.Contains(addrs, TunAddress4) {
				t.Errorf("tun addresses %v lack %s", addrs, TunAddress4)
			}
			if got := slices.Contains(addrs, TunAddress6); got != egress {
				t.Errorf("tun addresses %v: has %s = %v, want %v", addrs, TunAddress6, got, egress)
			}
			if !hasMixedListener(built, "::1") {
				t.Error("no mixed listener on ::1; the egress adapter must not decide the loopback listener")
			}
		})
	}
}

func hasMixedListener(built *option.Options, listen string) bool {
	for _, inbound := range built.Inbounds {
		if inbound.Type != C.TypeMixed {
			continue
		}
		opts := inbound.Options.(*option.HTTPMixedInboundOptions)
		if opts.Listen != nil && netip.Addr(*opts.Listen).String() == listen {
			return true
		}
	}
	return false
}

// The real tables on this machine. The probe reads the IPv6 state from the
// adapter record; the system's interface list is an independent view of the
// same fact (an adapter running IPv6 always has at least a link-local address),
// so the two must agree for the adapter the probe picks.
func TestHostEgressRoutesAgreeWithTheInterfaceList(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the egress probe reads Windows tables only")
	}
	routes, err := hostEgressRoutes()
	if err != nil {
		t.Fatalf("hostEgressRoutes: %v", err)
	}
	route, found := defaultEgress(routes)
	if !found {
		t.Skip("no IPv4 default route on this machine")
	}
	t.Logf("default egress: %q (index %d, metric %d), IPv6 enabled: %v", route.alias, route.index, route.metric, route.ipv6Enabled)

	iface, err := net.InterfaceByIndex(int(route.index))
	if err != nil {
		t.Fatalf("InterfaceByIndex(%d): %v", route.index, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	hasIPv6 := false
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() == nil {
			hasIPv6 = true
		}
	}
	if hasIPv6 != route.ipv6Enabled {
		t.Errorf("%q: probe says IPv6 enabled = %v, but its addresses %v say %v", route.alias, route.ipv6Enabled, addrs, hasIPv6)
	}
}
