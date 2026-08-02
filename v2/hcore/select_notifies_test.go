package hcore

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// SelectOutbound must tell the monitoring subsystem the group changed.
//
// Companion to TestSelectOutboundSwitchesAndNotifies in v2/config, which starts
// a real box and proves SignalChange("") wakes a SubscribeGroup("") listener.
// That one pins the CONTRACT; this one pins the CALL SITE, which is what
// actually regressed — the notification here sat commented out
// (`urltestHistory.Observer().Emit(2)`) and the UI silently stopped following
// the selector after the sing-box 1.14 bump.
//
// Source-level for the same reason as debug_gating_test.go: exercising it for
// real needs a started HiddifyInstance with a live gRPC service, and the
// property worth protecting is simply that the call has not been deleted or
// commented out again.
func TestSelectOutboundSignalsMonitoring(t *testing.T) {
	src, err := os.ReadFile("commands.go")
	if err != nil {
		t.Fatal(err)
	}
	// stripComments is shared with debug_gating_test.go — a commented-out call
	// must not pass, which is not hypothetical: the notification this test guards
	// spent the bump commented out.
	body := selectOutboundBody(t, stripComments(string(src)))

	if !strings.Contains(body, "SignalChange") {
		t.Fatal(`HiddifyInstance.SelectOutbound no longer calls monitoring SignalChange.

Without it the selector switches but nothing streaming group state is told, so
the app keeps showing the previously active node — selecting a node looks like
it does nothing. See the comment at the call site.`)
	}

	// "" is the synthetic all-outbounds group monitoring builds in Start(), and
	// the one AllProxiesInfoStream subscribes to. Signalling only the group tag
	// never reaches it.
	if !regexp.MustCompile(`SignalChange\(\s*""\s*\)`).MatchString(body) {
		t.Error(`SelectOutbound signals monitoring but not SignalChange("").

AllProxiesInfoStream subscribes with SubscribeGroup(""), and SignalChange
notifies one group's channel only, so the UI stream would not be woken.`)
	}
}

// selectOutboundBody returns the text of HiddifyInstance.SelectOutbound, so an
// unrelated SignalChange elsewhere in the file cannot satisfy the assertions.
func selectOutboundBody(t *testing.T, src string) string {
	t.Helper()
	const sig = "func (h *HiddifyInstance) SelectOutbound("
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("HiddifyInstance.SelectOutbound not found — was it renamed? Update this test with it.")
	}
	rest := src[i+len(sig):]
	if j := strings.Index(rest, "\nfunc "); j >= 0 {
		return rest[:j]
	}
	return rest
}
