package config

import (
	"context"

	C "github.com/sagernet/sing-box/constant"
)

type platformTunKey struct{}

// WithPlatformTun records whether the config built under ctx is for a core whose
// tun device the operating system provides — a Network Extension on Apple
// platforms, a VpnService on Android — rather than one sing-box opens itself.
//
// hcore sets it from whether a libbox platform interface is registered, the same
// test StartService uses to hand that interface to sing-box. It is a context
// value and not a HiddifyOptions field because it describes the process the core
// runs in, not a preference: nothing the client or a subscription sends should
// be able to change it.
//
// A context without it reads as false, which is the desktop in-process core and
// what every golden config is built with.
func WithPlatformTun(ctx context.Context, managed bool) context.Context {
	return context.WithValue(ctx, platformTunKey{}, managed)
}

func platformTun(ctx context.Context) bool {
	managed, _ := ctx.Value(platformTunKey{}).(bool)
	return managed
}

// buildPlatform holds the OS facts the builder branches on, as values rather
// than sing-box's compile-time C.Is* constants, so each decision below can be
// asserted for every platform from whichever host runs the tests.
type buildPlatform struct {
	linux, android, darwin, ios bool
}

var hostPlatform = buildPlatform{
	linux:   C.IsLinux,
	android: C.IsAndroid,
	darwin:  C.IsDarwin,
	ios:     C.IsIos,
}

// macOSNetworkExtension reports whether the core runs inside the macOS
// packet-tunnel extension. C.IsDarwin is true on iOS as well, hence the !ios.
func (p buildPlatform) macOSNetworkExtension(managed bool) bool {
	return managed && p.darwin && !p.ios
}

// autoDetectInterface reports whether outbound dials are bound to the detected
// default interface. Off wherever the platform owns the tunnel.
//
// With a platform interface registered, sing-box takes the default interface
// from the PLATFORM's monitor (route/network.go), and RaynTunnel never starts
// one — ExtensionPlatformInterface.startDefaultInterfaceMonitor returns at once.
// The default interface then stays nil and every dial fails with ErrNoRoute, so
// the tunnel comes up and carries nothing. iOS and Android were excluded by OS
// from the start; the macOS extension is excluded by `managed`. There is nothing
// to bind there anyway: the system keeps a tunnel provider's own sockets out of
// its tunnel.
func (p buildPlatform) autoDetectInterface(managed, tun bool) bool {
	return !p.android && !p.ios && !managed && tun
}

// redirectInbound reports whether the loopback redirect listener is built.
//
// It serves nothing inside a Network Extension, where the tunnel reaches the
// core through the platform rather than a redirect. Skipped for the macOS
// extension only. The iOS extension builds it too today (C.IsDarwin is true on
// iOS) and equally for nothing, but removing it there waits for the next iOS
// core rebuild rather than riding in with the macOS port.
func (p buildPlatform) redirectInbound(port uint16, managed bool) bool {
	return (p.linux || p.darwin) && !p.android && !p.macOSNetworkExtension(managed) && port > 0
}
