//go:build raynconfigdump

package hcore

import (
	"fmt"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux
	"os"
	"runtime/pprof"
)

// Diagnostic facilities that exist ONLY in a core built with
// `-tags raynconfigdump`. Both used to be reachable from a shipped build.
//
// The gate is a build tag rather than a runtime flag for the reason already
// documented on the built-config dump: `static.debug` / `SetupRequest.Debug` are
// set by the Settings debug switch and implied by choosing log level debug/trace
// (buildconfighelper.go), and the loopback gRPC channel is unauthenticated. A
// build tag is the only gate a shipped binary cannot be talked into opening.

// dumpGoroutines writes a full goroutine dump to data/<name> under the working
// path. Call sites: service start, and service stop when CloseService fails.
//
// Previously the start dump was gated on `static.debug` and the stop dump was
// **not gated at all** — it fired in shipped builds on any failed stop.
//
// What it discloses is architecture, not credentials, and that is still worth
// withholding: `pprof.WriteTo(f, 2)` emits full stacks with Go function names and
// package paths, which survive the `-w -s` ldflags because stack traces need the
// pclntab. The result names `github.com/sagernet/sing-box/...` and
// `github.com/hiddify/hiddify-core/...` in cleartext, along with every protocol
// compiled in — undoing, in one file on disk, the de-Hiddify renaming applied to
// the AAR and the Wire protos to defeat clone detection.
//
// Dumps written by older builds are deleted at launch by the at-rest migration.
func dumpGoroutines(workingPath string, name string) {
	path := fmt.Sprint(workingPath, "/data/", name)
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	_ = pprof.Lookup("goroutine").WriteTo(f, 2)
	Log(LogLevel_WARNING, LogType_CORE,
		"goroutine dump written to ", path, " — this core is built with raynconfigdump and MUST NOT be shipped")
}

// startDebugHTTPServer serves the Go pprof suite on localhost:6060.
//
// This was the sharpest of the debug facilities, and the least visible: a blank
// `net/http/pprof` import registers /debug/pprof/{goroutine,heap,profile,trace,
// cmdline,symbol} on the default mux, and a shipped build served all of it the
// moment the user enabled Debug mode. Unlike a dump on disk there is nothing to
// sweep afterwards — it is a live, unauthenticated listener, reachable by any
// local process, which on Android means any other app on the device.
//
// The import now lives in this file, so a shipped core does not even register the
// handlers.
func startDebugHTTPServer(enabled bool) {
	if !enabled {
		return
	}
	Log(LogLevel_WARNING, LogType_CORE,
		"pprof debug server listening on localhost:6060 — this core is built with raynconfigdump and MUST NOT be shipped")
	go func() {
		_ = http.ListenAndServe("localhost:6060", nil)
	}()
}
