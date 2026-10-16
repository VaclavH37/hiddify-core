package config

import "fmt"

// EgressRouting describes the routing switches on the adapter the core's own
// connections leave through: the adapter every outbound socket is bound to.
//
// Why it matters, reproduced on 2026-10-16 (Windows 11 on Wi-Fi, packet
// captures in both states): when IPv4 forwarding is on for that adapter,
// Windows stops honouring the IP_UNICAST_IF binding sing puts on each socket.
// The core's hub and direct dials then follow the tunnel's default route into
// the tun, still carrying the adapter's address, and the Windows self-loop
// guard in setRoutingOptions refuses them. The tunnel carries nothing while
// the app reads "Connected". Every hub SYN went to the wintun adapter instead
// of the Wi-Fi card; turning forwarding off on the adapter alone moved them
// back within a second, with no reconnect.
//
// The Routing and Remote Access service ("Incoming Connections") turns
// forwarding on for every adapter, but forwarding alone is enough: the same
// failure followed `Set-NetIPInterface -Forwarding Enabled` with the service
// off. Forwarding on the tun itself, which sing-tun always enables, plays no
// part.
//
// Nothing here changes a setting. The app reads this to explain a dead tunnel
// and to stop treating it as a blocked hub.
type EgressRouting struct {
	// Checked is false outside Windows, and when the tables could not be read.
	// Nothing else in the struct means anything without it.
	Checked bool `json:"checked"`
	// Index is the adapter's interface index, which Windows shares between
	// IPv4 and IPv6, and which `netsh interface ipv4 set interface` accepts.
	Index uint32 `json:"index"`
	// Alias is the adapter's friendly name as Windows shows it, so it is
	// localised ("Wi-Fi", "WLAN", ...).
	Alias string `json:"alias"`
	// Forwarding is IPv4 forwarding: the switch the reproduction proved.
	Forwarding bool `json:"forwarding"`
	// Forwarding6 and WeakHostSend are reported, never acted on: neither has
	// been tested on its own. IPv6 forwarding is the one to watch, because the
	// self-loop guard covers IPv4 only.
	Forwarding6  bool `json:"forwarding6"`
	WeakHostSend bool `json:"weak_host_send"`
}

// BlocksTunnel reports whether the egress adapter is in the state proven to
// send the core's own connections back into the tunnel.
func (r EgressRouting) BlocksTunnel() bool {
	return r.Checked && r.Forwarding
}

func (r EgressRouting) String() string {
	if !r.Checked {
		return "egress adapter: unknown"
	}
	return fmt.Sprintf("egress adapter %q (index %d): forwarding=%s forwarding6=%s weak-host-send=%s",
		r.Alias, r.Index, onOff(r.Forwarding), onOff(r.Forwarding6), onOff(r.WeakHostSend))
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// defaultConnectedEgress is defaultEgress plus the one condition of sing-tun's
// default-interface monitor that defaultEgress leaves out: the adapter's IPv4
// interface must report Connected (sing-tun monitor_windows.go checkUpdate).
// The callback answers it, so the choice stays testable without the system
// tables.
func defaultConnectedEgress(routes []egressRoute, connected func(index uint32) bool) (egressRoute, bool) {
	var eligible []egressRoute
	for _, r := range routes {
		if connected(r.index) {
			eligible = append(eligible, r)
		}
	}
	return defaultEgress(eligible)
}
