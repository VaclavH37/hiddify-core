package raynurltest

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
)

// usable reports whether a stored probe result can rank an outbound.
//
// The imported fork never deletes a history entry. A failed probe is stored as
// monitoring.TimeoutDelay (65535) by both the url-test group and the
// monitoring service, and the fork's urltest.URLTest reports a probe that was
// cancelled between the dial and the request as a 0 ms success. Upstream's
// Select assumes a failed outbound has no entry at all, so it ranks the
// sentinel in uint16 arithmetic, where 65535 + tolerance wraps to
// tolerance - 1 and a dead exit beats every live one. Neither value is a
// measurement, and neither may pick an exit.
func usable(history *adapter.URLTestHistory) bool {
	return history != nil && history.Delay > 0 && history.Delay < monitoring.TimeoutDelay
}

// selectLowest picks the tag with the lowest usable delay, keeping incumbent
// unless a candidate is more than tolerance ms faster (the hysteresis the
// `lowest` group exists for). Arithmetic is int, so no sum can wrap. Returns
// ("", false) when no tag has a usable result; the caller decides what to do
// with nothing.
func selectLowest(order []string, incumbent string, history func(tag string) *adapter.URLTestHistory, tolerance uint16) (string, bool) {
	best := ""
	bestDelay := 0
	if incumbent != "" {
		if h := history(incumbent); usable(h) {
			best, bestDelay = incumbent, int(h.Delay)
		}
	}
	for _, tag := range order {
		h := history(tag)
		if !usable(h) {
			continue
		}
		delay := int(h.Delay)
		if best == "" || bestDelay > delay+int(tolerance) {
			best, bestDelay = tag, delay
		}
	}
	return best, best != ""
}
