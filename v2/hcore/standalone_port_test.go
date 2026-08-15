package hcore

import (
	"net"
	"strconv"
	"testing"
)

// The CLI's core is a SEPARATE PROCESS from the app's, so its listener must not
// share a port with either of the app's cores. Loopback is not isolated between
// processes, so a shared port means they fight for the bind and the loser's
// client attaches to the winner's core — the defect the app's port move exists
// to remove, made harder to spot because both processes would be ours.
//
// The app's ports live in Dart (CoreInterfaceMobile), Kotlin (Settings) and
// Swift (ExtensionProvider); Go never sees them, so they are restated here.
// Restating them is the point: this fails if someone "tidies up" by pointing the
// CLI at the app's port.
func TestStandaloneListenAddressDoesNotCollide(t *testing.T) {
	const (
		appForegroundPort = "21978"
		appBackgroundPort = "21979"
		upstreamHiddify   = "17078"
	)

	host, port, err := net.SplitHostPort(StandaloneListenAddress)
	if err != nil {
		t.Fatalf("StandaloneListenAddress %q is not host:port: %v", StandaloneListenAddress, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1 — this must never be reachable off the machine", host)
	}

	switch port {
	case appForegroundPort, appBackgroundPort:
		t.Errorf("port %s is one of the APP's cores; the CLI is a separate process and would "+
			"fight it for the bind", port)
	case upstreamHiddify:
		t.Errorf("port %s is upstream Hiddify's; any Hiddify CLI on the same machine collides", port)
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q is not numeric: %v", port, err)
	}
	// Below the ephemeral range so the OS cannot hand it to something else, and
	// above the privileged range so binding needs no elevation.
	if n <= 1024 || n >= 49152 {
		t.Errorf("port %d is outside the usable fixed range (1025..49151)", n)
	}
}
