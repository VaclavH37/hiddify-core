//go:build windows

package config

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IF_TYPE_PROP_VIRTUAL, which golang.org/x/sys/windows does not define. Wintun
// adapters, ours included, report it.
const ifTypePropVirtual = 53

// hostEgressRoutes lists every IPv4 default route with the adapter it leaves
// through, from the same two tables sing-tun's monitor reads: the IPv4 route
// table, and the adapters for their state and metrics.
func hostEgressRoutes() ([]egressRoute, error) {
	adapters, err := adaptersByIPv4Index()
	if err != nil {
		return nil, err
	}

	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, os.NewSyscallError("getipforwardtable2", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	var routes []egressRoute
	for _, row := range table.Rows() {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		adapter, ok := adapters[row.InterfaceIndex]
		if !ok {
			continue
		}
		routes = append(routes, egressRoute{
			index:       row.InterfaceIndex,
			alias:       windows.UTF16PtrToString(adapter.FriendlyName),
			up:          adapter.OperStatus == windows.IfOperStatusUp,
			virtual:     adapter.IfType == ifTypePropVirtual || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK,
			metric:      row.Metric + adapter.Ipv4Metric,
			ipv6Enabled: adapter.Ipv6IfIndex != 0, // zero when IPv6 is not bound to the adapter
		})
	}
	return routes, nil
}

// adaptersByIPv4Index returns every adapter keyed by its IPv4 interface index,
// the index route rows carry. The entries point into one buffer that stays
// alive as long as the map does.
func adaptersByIPv4Index() (map[uint32]*windows.IpAdapterAddresses, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(15000)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == nil {
			adapters := make(map[uint32]*windows.IpAdapterAddresses)
			for a := first; a != nil; a = a.Next {
				if a.IfIndex != 0 {
					adapters[a.IfIndex] = a
				}
			}
			return adapters, nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size <= uint32(len(buf)) {
			return nil, os.NewSyscallError("getadaptersaddresses", err)
		}
	}
}
