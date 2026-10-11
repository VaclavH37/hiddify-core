package config

// egressRoute is one IPv4 default route joined with the adapter it leaves
// through: the facts sing-tun's default-interface monitor chooses by, plus
// whether that adapter runs IPv6 at all.
type egressRoute struct {
	index       uint32
	alias       string
	up          bool
	virtual     bool   // a virtual (tun) or loopback adapter: never the default
	metric      uint32 // route metric + the adapter's IPv4 interface metric
	ipv6Enabled bool
}

// defaultEgress picks the route sing-tun's Windows monitor would pick
// (sing-tun monitor_windows.go checkUpdate): an IPv4 default route through an
// adapter that is up and not virtual or loopback, lowest combined metric, the
// first one on a tie. found is false when no route qualifies.
//
// The monitor also requires the adapter's IPv4 interface to report Connected,
// which golang.org/x/sys/windows has no call for. Up stands in for it.
func defaultEgress(routes []egressRoute) (route egressRoute, found bool) {
	lowest := ^uint32(0)
	for _, r := range routes {
		if !r.up || r.virtual {
			continue
		}
		if r.metric < lowest {
			lowest, route, found = r.metric, r, true
		}
	}
	return route, found
}

// hostEgressIPv6 reports whether IPv6 is enabled on the adapter outbound dials
// are bound to: the default interface auto_detect_interface picks.
//
// When it is not, the direct outbound cannot hold IPv6 to that adapter. A
// direct UDP dial opens a dual-stack socket on no particular local address;
// sing binds it to the adapter with IP_UNICAST_IF, then tries IPV6_UNICAST_IF
// and deliberately ignores a failure ("a workaround for windows disable
// interface ipv6", common/control/bind_windows.go). That is exactly the call
// that fails when IPv6 is unticked on the adapter. The socket's IPv6 then
// follows the routing table into our own tun's ::/0, arrives from the tun's
// ULA with a new source port, matches the same direct rule, and is sent again
// from a new socket. One packet sustains it indefinitely.
//
// Seen in a customer's crash dumps (2026-10): IPv6 UDP from a peer-to-peer app
// to regional addresses, ~11,000 IPv6 sockets and no IPv4 ones, the tunnel
// carrying nothing, then runtime.checkmcount. Reproduced on a VM by unticking
// IPv6 on its adapter: one packet held ~1,024 sockets (udpnat2's table) open
// with nothing else sending. The same VM with IPv6 ticked but no global
// address did not loop, so the adapter setting is the condition, not the lack
// of IPv6 internet.
//
// Not claiming IPv6 on such a host loses nothing: without IPv6 on its egress
// adapter the host has no native IPv6 to leak. The cost is a session that
// starts on such an adapter and later moves to one with IPv6, whose IPv6
// bypasses the tunnel until the next connect.
//
// Anything the probe cannot answer reads as true, which is the behaviour
// before this check existed.
func hostEgressIPv6() bool {
	routes, err := hostEgressRoutes()
	if err != nil {
		return true
	}
	route, found := defaultEgress(routes)
	if !found {
		return true
	}
	return route.ipv6Enabled
}
