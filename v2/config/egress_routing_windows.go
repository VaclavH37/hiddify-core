//go:build windows

package config

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// golang.org/x/sys/windows defines MIB_IPINTERFACE_ROW but has no wrapper for
// the call that fills it.
var procGetIpInterfaceEntry = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpInterfaceEntry")

// ipInterfaceRow reads one address family's row for an interface. ok is false
// when the call fails, which is also what an adapter with that family unbound
// returns.
//
// windows.MibIpInterfaceRow matches the native layout through ReachableTime,
// which covers every field read here (a test pins their offsets). Its offload
// fields are declared wider than the native one-byte types, so the Go struct
// is 8 bytes larger: harmless for a read, where the buffer is only bigger than
// needed. Never pass it to SetIpInterfaceEntry.
func ipInterfaceRow(family uint16, index uint32) (row windows.MibIpInterfaceRow, ok bool) {
	if procGetIpInterfaceEntry.Find() != nil {
		return row, false
	}
	// Family and the index are all the call needs on input: it reads by LUID
	// when that is set and by index otherwise. InitializeIpInterfaceEntry only
	// matters before a Set.
	row.Family = family
	row.InterfaceIndex = index
	status, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	return row, status == uintptr(windows.NO_ERROR)
}

// EgressRoutingFor reads the routing switches of the adapter with this index.
// alias is reported as given.
func EgressRoutingFor(index uint32, alias string) EgressRouting {
	if index == 0 {
		return EgressRouting{}
	}
	v4, ok := ipInterfaceRow(windows.AF_INET, index)
	if !ok {
		return EgressRouting{}
	}
	routing := EgressRouting{
		Checked:      true,
		Index:        index,
		Alias:        alias,
		Forwarding:   v4.ForwardingEnabled != 0,
		WeakHostSend: v4.WeakHostSend != 0,
	}
	if v6, ok := ipInterfaceRow(windows.AF_INET6, index); ok {
		routing.Forwarding6 = v6.ForwardingEnabled != 0
	}
	return routing
}

// HostEgressRouting picks the egress adapter from the system tables, the way
// sing-tun's monitor would, and reads its switches. It is the answer when no
// tunnel is running; while one is, hcore asks the running monitor instead.
func HostEgressRouting() EgressRouting {
	routes, err := hostEgressRoutes()
	if err != nil {
		return EgressRouting{}
	}
	route, found := defaultConnectedEgress(routes, func(index uint32) bool {
		row, ok := ipInterfaceRow(windows.AF_INET, index)
		return ok && row.Connected != 0
	})
	if !found {
		return EgressRouting{}
	}
	return EgressRoutingFor(route.index, route.alias)
}
