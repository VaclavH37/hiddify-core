package raynurltest

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
)

// The bug this package exists for: the fork stores a failed probe as 65535
// and upstream's Select adds the tolerance to it in uint16, so a dead exit
// listed after a live one wins. Every case here runs against the pure
// selection with the shipped tolerance unless it says otherwise.
func TestSelectLowest(t *testing.T) {
	const dead = monitoring.TimeoutDelay
	cases := []struct {
		name      string
		order     []string
		delays    map[string]uint16 // absent = never probed
		incumbent string
		tolerance uint16
		want      string
		ok        bool
	}{
		{
			name:      "a dead exit after a live incumbent does not displace it",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 250, "b": dead},
			incumbent: "a",
			want:      "a", ok: true,
		},
		{
			name:      "the last dead exit in the list never wins",
			order:     []string{"a", "b", "c"},
			delays:    map[string]uint16{"a": 250, "b": 300, "c": dead},
			incumbent: "",
			want:      "a", ok: true,
		},
		{
			name:      "a dead incumbent is left for a live exit",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": dead, "b": 300},
			incumbent: "a",
			want:      "b", ok: true,
		},
		{
			name:      "all dead: nothing to choose",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": dead, "b": dead},
			incumbent: "a",
			want:      "", ok: false,
		},
		{
			name:   "never probed: nothing to choose",
			order:  []string{"a", "b"},
			delays: map[string]uint16{},
			want:   "", ok: false,
		},
		{
			name:      "a 0 ms result is a cancelled probe, not a winner",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 0, "b": 400},
			incumbent: "",
			want:      "b", ok: true,
		},
		{
			name:      "a 0 ms incumbent is not kept",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 0, "b": 400},
			incumbent: "a",
			want:      "b", ok: true,
		},
		{
			name:      "a candidate inside the tolerance band keeps the incumbent",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 200, "b": 150},
			incumbent: "a",
			want:      "a", ok: true,
		},
		{
			name:      "a candidate outside the tolerance band replaces the incumbent",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 200, "b": 90},
			incumbent: "a",
			want:      "b", ok: true,
		},
		{
			name:   "no incumbent: the minimum",
			order:  []string{"a", "b", "c"},
			delays: map[string]uint16{"a": 300, "b": 120, "c": 180},
			want:   "b", ok: true,
		},
		{
			name:      "near the top of the range nothing wraps",
			order:     []string{"a", "b"},
			delays:    map[string]uint16{"a": 65534, "b": dead},
			incumbent: "a",
			want:      "a", ok: true,
		},
		{
			name:      "an incumbent that is no longer listed still counts as the incumbent",
			order:     []string{"b"},
			delays:    map[string]uint16{"a": 100, "b": 150},
			incumbent: "a",
			want:      "a", ok: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tolerance := tc.tolerance
			if tolerance == 0 {
				tolerance = 100
			}
			history := func(tag string) *adapter.URLTestHistory {
				delay, probed := tc.delays[tag]
				if !probed {
					return nil
				}
				return &adapter.URLTestHistory{Delay: delay}
			}
			got, ok := selectLowest(tc.order, tc.incumbent, history, tolerance)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("selectLowest = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestUsable(t *testing.T) {
	if usable(nil) {
		t.Fatal("nil history is not usable")
	}
	if usable(&adapter.URLTestHistory{Delay: 0}) {
		t.Fatal("0 ms is not a measurement")
	}
	if usable(&adapter.URLTestHistory{Delay: monitoring.TimeoutDelay}) {
		t.Fatal("the failure sentinel is not a measurement")
	}
	if !usable(&adapter.URLTestHistory{Delay: 1}) || !usable(&adapter.URLTestHistory{Delay: monitoring.TimeoutDelay - 1}) {
		t.Fatal("every value strictly between is a measurement")
	}
}
