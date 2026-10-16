//go:build windows

package config

import (
	"net"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The fields EgressRoutingFor reads must sit where Windows writes them. These
// are the native MIB_IPINTERFACE_ROW offsets on 64-bit Windows; the struct as
// a whole is larger in Go (see ipInterfaceRow), which a read tolerates.
func TestMibIpInterfaceRowOffsetsMatchWindows(t *testing.T) {
	var row windows.MibIpInterfaceRow
	offsets := []struct {
		field string
		got   uintptr
		want  uintptr
	}{
		{"Family", unsafe.Offsetof(row.Family), 0},
		{"InterfaceIndex", unsafe.Offsetof(row.InterfaceIndex), 16},
		{"ForwardingEnabled", unsafe.Offsetof(row.ForwardingEnabled), 41},
		{"WeakHostSend", unsafe.Offsetof(row.WeakHostSend), 42},
		{"Connected", unsafe.Offsetof(row.Connected), 156},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("%s at offset %d, Windows has it at %d", o.field, o.got, o.want)
		}
	}
}

// The real tables on this machine: the probe names an adapter the system's
// interface list knows by the same name.
//
// To check the switches themselves, set RAYN_EXPECT_FORWARDING to 1 or 0 after
// changing the adapter (as administrator):
//
//	Set-NetIPInterface -InterfaceAlias Wi-Fi -Forwarding Enabled
//	$env:RAYN_EXPECT_FORWARDING = 1; go test ./v2/config -run TestHostEgressRouting
//	Set-NetIPInterface -InterfaceAlias Wi-Fi -Forwarding Disabled
func TestHostEgressRoutingReadsThisMachine(t *testing.T) {
	routing := HostEgressRouting()
	if !routing.Checked {
		routes, err := hostEgressRoutes()
		if err == nil {
			if _, found := defaultEgress(routes); !found {
				t.Skip("no IPv4 default route on this machine")
			}
		}
		t.Fatalf("HostEgressRouting() unchecked on a machine with a default route (tables error: %v)", err)
	}
	t.Logf("%v", routing)

	iface, err := net.InterfaceByIndex(int(routing.Index))
	if err != nil {
		t.Fatalf("InterfaceByIndex(%d): %v", routing.Index, err)
	}
	if iface.Name != routing.Alias {
		t.Errorf("index %d: probe says %q, the interface list says %q", routing.Index, routing.Alias, iface.Name)
	}

	switch os.Getenv("RAYN_EXPECT_FORWARDING") {
	case "1":
		if !routing.Forwarding {
			t.Errorf("%q: forwarding read as off, expected on", routing.Alias)
		}
	case "0":
		if routing.Forwarding {
			t.Errorf("%q: forwarding read as on, expected off", routing.Alias)
		}
	}
}

func TestEgressRoutingForLoopbackAnswers(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		got := EgressRoutingFor(uint32(iface.Index), iface.Name)
		if !got.Checked || got.Index != uint32(iface.Index) || got.Alias != iface.Name {
			t.Errorf("EgressRoutingFor(%d, %q) = %+v", iface.Index, iface.Name, got)
		}
		return
	}
	t.Skip("no loopback interface listed")
}

func TestEgressRoutingForUnknownIndexIsUnchecked(t *testing.T) {
	if got := EgressRoutingFor(0, ""); got.Checked {
		t.Errorf("index 0: %+v, want unchecked", got)
	}
	if got := EgressRoutingFor(0x7ffffff0, "nothing"); got.Checked {
		t.Errorf("an index no adapter has: %+v, want unchecked", got)
	}
}
