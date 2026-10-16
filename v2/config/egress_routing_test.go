package config

import (
	"encoding/json"
	"runtime"
	"slices"
	"testing"
)

// The desktop app parses this JSON (raynEgressRouting); renaming a field would
// silently turn every answer into "nothing to report".
func TestEgressRoutingJSONFieldNames(t *testing.T) {
	payload, err := json.Marshal(EgressRouting{Checked: true, Index: 4, Alias: "Wi-Fi", Forwarding: true})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	want := []string{"alias", "checked", "forwarding", "forwarding6", "index", "weak_host_send"}
	if !slices.Equal(keys, want) {
		t.Errorf("JSON keys %v, want %v", keys, want)
	}
	if fields["alias"] != "Wi-Fi" || fields["index"] != float64(4) || fields["forwarding"] != true {
		t.Errorf("JSON %s does not carry the values it was given", payload)
	}
}

// Only IPv4 forwarding was proven to break the tunnel; the other switches are
// reported, and an unchecked answer never blocks anything.
func TestBlocksTunnelOnlyOnCheckedIPv4Forwarding(t *testing.T) {
	cases := []struct {
		name    string
		routing EgressRouting
		want    bool
	}{
		{"IPv4 forwarding", EgressRouting{Checked: true, Forwarding: true}, true},
		{"nothing on", EgressRouting{Checked: true}, false},
		{"IPv6 forwarding only", EgressRouting{Checked: true, Forwarding6: true}, false},
		{"weak-host send only", EgressRouting{Checked: true, WeakHostSend: true}, false},
		{"not checked", EgressRouting{Forwarding: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.routing.BlocksTunnel(); got != tc.want {
				t.Errorf("BlocksTunnel() = %v, want %v", got, tc.want)
			}
		})
	}
}

// sing-tun's monitor skips an adapter whose IPv4 interface is not Connected;
// without that, a disconnected adapter with a lower metric would be named.
func TestDefaultConnectedEgressSkipsDisconnectedAdapters(t *testing.T) {
	ethernet := egressRoute{index: 9, alias: "Ethernet", up: true, metric: 25}
	wifi := egressRoute{index: 12, alias: "Wi-Fi", up: true, metric: 35}
	only := func(indexes ...uint32) func(uint32) bool {
		return func(index uint32) bool { return slices.Contains(indexes, index) }
	}

	cases := []struct {
		name      string
		connected func(uint32) bool
		wantAlias string
		wantFound bool
	}{
		{"lowest metric when both are connected", only(9, 12), "Ethernet", true},
		{"a disconnected lower metric is skipped", only(12), "Wi-Fi", true},
		{"nothing connected", only(), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := defaultConnectedEgress([]egressRoute{ethernet, wifi}, tc.connected)
			if found != tc.wantFound || got.alias != tc.wantAlias {
				t.Errorf("defaultConnectedEgress = (%q, %v), want (%q, %v)", got.alias, found, tc.wantAlias, tc.wantFound)
			}
		})
	}
}

func TestEgressRoutingIsUncheckedOutsideWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("covered by the Windows tests")
	}
	if got := HostEgressRouting(); got.Checked {
		t.Errorf("HostEgressRouting() = %+v, want unchecked", got)
	}
	if got := EgressRoutingFor(1, "lo"); got.Checked {
		t.Errorf("EgressRoutingFor() = %+v, want unchecked", got)
	}
}
