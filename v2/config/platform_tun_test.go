package config

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

var (
	platformWindows = buildPlatform{}
	platformLinux   = buildPlatform{linux: true}
	platformAndroid = buildPlatform{linux: true, android: true}
	platformIOS     = buildPlatform{darwin: true, ios: true}
	platformMacOS   = buildPlatform{darwin: true}
)

// The decisions, for every platform, from any host. The row that matters is the
// macOS extension: auto-detect there makes every dial fail with ErrNoRoute,
// because RaynTunnel never starts the platform's default-interface monitor.
// Every other row pins today's behaviour so the gate stays strictly additive.
func TestPlatformTunDecisions(t *testing.T) {
	cases := []struct {
		name       string
		platform   buildPlatform
		managed    bool
		autoDetect bool
		redirect   bool
	}{
		{"windows desktop", platformWindows, false, true, false},
		{"linux desktop", platformLinux, false, true, true},
		{"android vpnservice", platformAndroid, true, false, false},
		{"android unmanaged", platformAndroid, false, false, false},
		// The iOS extension keeps its idle redirect listener for now; see
		// redirectInbound.
		{"ios extension", platformIOS, true, false, true},
		{"ios front core", platformIOS, false, false, true},
		{"macos extension", platformMacOS, true, false, false},
		{"macos in-process", platformMacOS, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.platform.autoDetectInterface(tc.managed, true); got != tc.autoDetect {
				t.Errorf("autoDetectInterface = %v, want %v", got, tc.autoDetect)
			}
			if got := tc.platform.redirectInbound(12336, tc.managed); got != tc.redirect {
				t.Errorf("redirectInbound = %v, want %v", got, tc.redirect)
			}
			if tc.platform.autoDetectInterface(tc.managed, false) {
				t.Error("autoDetectInterface is on with no tun")
			}
			if tc.platform.redirectInbound(0, tc.managed) {
				t.Error("redirectInbound is on with no port")
			}
		})
	}
}

func TestMacOSNetworkExtensionExcludesIOS(t *testing.T) {
	if platformIOS.macOSNetworkExtension(true) {
		t.Error("the iOS extension reads as the macOS extension; C.IsDarwin is true on iOS")
	}
	if !platformMacOS.macOSNetworkExtension(true) {
		t.Error("the macOS extension is not recognised")
	}
	if platformMacOS.macOSNetworkExtension(false) {
		t.Error("an unmanaged macOS core reads as the extension")
	}
}

func TestHostPlatformMatchesSingBox(t *testing.T) {
	want := buildPlatform{linux: C.IsLinux, android: C.IsAndroid, darwin: C.IsDarwin, ios: C.IsIos}
	if hostPlatform != want {
		t.Errorf("hostPlatform = %+v, want %+v", hostPlatform, want)
	}
}

func TestPlatformTunDefaultsToUnmanaged(t *testing.T) {
	if platformTun(context.Background()) {
		t.Error("a context without WithPlatformTun reads as managed")
	}
	if !platformTun(WithPlatformTun(context.Background(), true)) {
		t.Error("WithPlatformTun(true) is not read back")
	}
}

func buildShipped(t *testing.T, ctx context.Context, extra func(*HiddifyOptions)) (*option.Options, error) {
	t.Helper()
	opts := DefaultHiddifyOptions()
	shipped(opts)
	if extra != nil {
		extra(opts)
	}
	return BuildConfig(ctx, opts, &ReadOptions{Options: outbounds(2)})
}

func mustBuildShipped(t *testing.T, ctx context.Context, extra func(*HiddifyOptions)) *option.Options {
	t.Helper()
	built, err := buildShipped(t, ctx, extra)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	return built
}

func tunOptions(t *testing.T, built *option.Options) *option.TunInboundOptions {
	t.Helper()
	for _, inbound := range built.Inbounds {
		if inbound.Type == C.TypeTun {
			return inbound.Options.(*option.TunInboundOptions)
		}
	}
	t.Fatal("no tun inbound in the built config")
	return nil
}

func hasRedirect(built *option.Options) bool {
	for _, inbound := range built.Inbounds {
		if inbound.Type == C.TypeRedirect {
			return true
		}
	}
	return false
}

// The config a platform-tun core builds, end to end on this host.
func TestBuildConfigUnderPlatformTun(t *testing.T) {
	built := mustBuildShipped(t, WithPlatformTun(t.Context(), true), nil)

	if built.Route.AutoDetectInterface {
		t.Error("auto_detect_interface is on for a platform tun")
	}
	if got, want := hasRedirect(built), hostPlatform.redirectInbound(12336, true); got != want {
		t.Errorf("redirect inbound present = %v, want %v on this host", got, want)
	}
}

// Marking the context unmanaged changes nothing: it is what every existing
// caller, and every golden config, already builds with.
func TestBuildConfigUnmanagedIsTheDefault(t *testing.T) {
	plain := mustBuildShipped(t, t.Context(), nil)
	unmanaged := mustBuildShipped(t, WithPlatformTun(t.Context(), false), nil)

	plainJSON, err := canonicalize(plain)
	if err != nil {
		t.Fatal(err)
	}
	unmanagedJSON, err := canonicalize(unmanaged)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plainJSON, unmanagedJSON) {
		t.Error("WithPlatformTun(false) builds a different config from a plain context")
	}
	if got, want := plain.Route.AutoDetectInterface, hostPlatform.autoDetectInterface(false, true); got != want {
		t.Errorf("auto_detect_interface = %v, want %v on this host", got, want)
	}
}

func TestTestRouteExcludeAddress(t *testing.T) {
	t.Run("absent by default", func(t *testing.T) {
		tun := tunOptions(t, mustBuildShipped(t, t.Context(), nil))
		if len(tun.RouteExcludeAddress) != 0 {
			t.Errorf("route_exclude_address = %v in a shipped config", tun.RouteExcludeAddress)
		}
	})

	t.Run("carried onto the tun", func(t *testing.T) {
		tun := tunOptions(t, mustBuildShipped(t, WithPlatformTun(t.Context(), true), func(o *HiddifyOptions) {
			o.TestRouteExcludeAddress = []string{"203.0.113.7/32", "2001:db8::/48"}
		}))
		want := []netip.Prefix{
			netip.MustParsePrefix("203.0.113.7/32"),
			netip.MustParsePrefix("2001:db8::/48"),
		}
		if !reflect.DeepEqual([]netip.Prefix(tun.RouteExcludeAddress), want) {
			t.Errorf("route_exclude_address = %v, want %v", tun.RouteExcludeAddress, want)
		}
	})

	t.Run("a malformed prefix fails the build", func(t *testing.T) {
		_, err := buildShipped(t, t.Context(), func(o *HiddifyOptions) {
			o.TestRouteExcludeAddress = []string{"203.0.113.7"}
		})
		if err == nil || !strings.Contains(err.Error(), "test-route-exclude-address") {
			t.Errorf("err = %v, want a test-route-exclude-address error", err)
		}
	})
}
