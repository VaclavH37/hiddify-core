package hcore

import (
	"github.com/hiddify/hiddify-core/v2/config"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// EgressRouting reports the routing switches on the adapter the core's own
// connections leave through; config.EgressRouting explains why they matter.
//
// While a tunnel runs, the adapter is the one sing-tun's default-interface
// monitor picked: exactly the one every outbound socket is bound to, so this
// cannot name a different adapter from the one in use. With no tunnel,
// config.HostEgressRouting makes the same choice from the system tables.
func EgressRouting() config.EgressRouting {
	if ctx := static.Context(); ctx != nil {
		if networkManager := service.FromContext[adapter.NetworkManager](ctx); networkManager != nil {
			if monitor := networkManager.InterfaceMonitor(); monitor != nil {
				if iface := monitor.DefaultInterface(); iface != nil && iface.Index > 0 {
					return config.EgressRoutingFor(uint32(iface.Index), iface.Name)
				}
			}
		}
	}
	return config.HostEgressRouting()
}

// logEgressRouting records the egress adapter's switches once per start: cheap
// support data in a diagnostics log, and a warning when they explain a tunnel
// that is about to carry nothing.
func logEgressRouting() {
	routing := EgressRouting()
	if !routing.Checked {
		return
	}
	if routing.BlocksTunnel() {
		Log(LogLevel_WARNING, LogType_CORE, routing,
			"; IPv4 forwarding on this adapter makes Windows route the core's own connections into the tunnel, which refuses them")
		return
	}
	Log(LogLevel_INFO, LogType_CORE, routing)
}
