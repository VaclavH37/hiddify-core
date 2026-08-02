//go:build !raynconfigdump

package hcore

// No-ops in every shippable core. See debugtools.go for what the enabled variants
// do and why they are behind a build tag rather than the runtime flags they used
// to use — `static.debug` for the start dump, nothing at all for the stop dump,
// and `SetupRequest.Debug` for the pprof listener.
//
// Note the enabled file is also where `net/http/pprof` is imported, so a shipped
// core does not register the /debug/pprof handlers on the default mux at all.

func dumpGoroutines(workingPath string, name string) {}

func startDebugHTTPServer(enabled bool) {}
