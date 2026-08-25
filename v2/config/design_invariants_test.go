package config

import (
	"bytes"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
)

// FakeIP must never appear in a built config.
//
// The hub runs domainStrategy:AsIs and needs real addresses; FakeIP hands the
// client a synthetic address and defers resolution, which breaks that topology.
// It was removed along with fakeip-remote-sites.srs and store_fakeip.
//
// The interesting half is the second subtest. config_option_repository.dart
// hardcodes `enableFakeDns: false` with the comment "The core ignores this value
// regardless" — an unverified claim that, if wrong, means a subscription
// override or a future caller could switch FakeIP back on. This pins the claim:
// asking for FakeIP explicitly must still not produce one.
func TestNoFakeIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"default", false},
		{"even when explicitly requested", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultHiddifyOptions()
			shipped(opts)
			opts.EnableFakeDNS = tc.enabled

			built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}

			// Checked as a DNS *server type*, not the old top-level dns.fakeip block.
			// sing-box removed that block in 1.14 -- option/dns.go now rejects it
			// outright -- and FakeIP became FakeIPDNSServerOptions, registered like any
			// other server. The invariant is unchanged; only where it would appear moved.
			if built.DNS != nil {
				for _, srv := range built.DNS.Servers {
					if srv.Type == C.DNSTypeFakeIP {
						t.Errorf("DNS server %q has type %q (EnableFakeDNS=%v); the hub runs "+
							"domainStrategy:AsIs and needs real addresses", srv.Tag, srv.Type, tc.enabled)
					}
				}
			}

			// Belt and braces: the typed check above only covers the field we know
			// about today. A rename or a second FakeIP knob elsewhere in the config
			// would slip past it, so also assert on the serialised form.
			raw, err := canonicalize(built)
			if err != nil {
				t.Fatal(err)
			}
			for _, needle := range []string{"fakeip", "fake_ip", "fake-ip"} {
				if bytes.Contains(bytes.ToLower(raw), []byte(needle)) {
					t.Errorf("built config mentions %q (EnableFakeDNS=%v)", needle, tc.enabled)
				}
			}
		})
	}
}

// sing-box has its own pprof listener, independent of anything this fork writes:
// setting experimental.debug.listen makes it serve /debug/pprof/* on that
// address. The handlers are registered in every shipped build regardless — the
// imported sing-box pulls net/http/pprof in from three packages and is not ours
// to edit — so `experimental.debug` being absent is what keeps them unreachable.
//
// This is the config-level half of TestNothingServesDefaultServeMux in v2/hcore.
// Both halves are needed: that one covers a listener we might start, this one
// covers a listener sing-box would start for us.
//
// The debug flag is exercised explicitly because that is the realistic
// regression: a future setExperimental that wires Debug through to
// experimental.debug would hand every debug-build user a profiling port, and
// with LogLevel already plumbed there is an obvious-looking place to do it.
// The Clash API must never open a socket, while cache-file and monitoring must
// always be configured.
//
// All three live in the same `if hopt.EnableClashApi` block in setExperimental,
// which is the trap: the flag reads as though it controls the API, but the two
// things this client actually depends on are inside it too. Cache-file carries
// the selector's persisted exit choice (Selector.Start -> LoadSelected), so
// losing it silently resets every user to auto-select; monitoring is what feeds
// the proxy list and the latency figures.
//
// The API itself is dead weight here -- the app drives the core over gRPC and no
// Dart code references the port -- so an external controller is a loopback HTTP
// listener nobody calls, on a loopback that is not isolated between apps. The
// server gates its listener on ExternalController != "" (clashapi/server.go),
// which is why an empty value keeps the ClashServer service registered for log
// observation and url-test history while opening nothing.
func TestClashAPIOpensNoSocketButCacheAndMonitoringSurvive(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if built.Experimental == nil {
		t.Fatal("experimental is nil; cache-file and monitoring are both gone with it")
	}

	if api := built.Experimental.ClashAPI; api == nil {
		t.Error("experimental.clash_api is nil; box.go registers the ClashServer on " +
			"`ClashAPI != nil || PlatformLogWriter != nil`, so a nil drops log observation " +
			"and the url-test history storage on any platform without a platform log writer")
	} else if api.ExternalController != "" {
		t.Errorf("experimental.clash_api.external_controller is %q; that opens an HTTP "+
			"server on loopback which nothing in this client calls", api.ExternalController)
	}

	if cf := built.Experimental.CacheFile; cf == nil || !cf.Enabled {
		t.Error("experimental.cache_file is absent or disabled; the selector's persisted " +
			"exit choice lives there, and without it every restart resets the user to auto-select")
	}
	if built.Experimental.Monitoring == nil {
		t.Error("experimental.monitoring is absent; it feeds the proxy list and latency figures")
	}
}

func TestExperimentalDebugListenerNeverConfigured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		level string
	}{
		{"shipped", "warn"},
		{"debug log level", "debug"},
		{"trace log level", "trace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := DefaultHiddifyOptions()
			shipped(opts)
			opts.LogLevel = tc.level

			built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}

			if built.Experimental != nil && built.Experimental.Debug != nil {
				t.Errorf("experimental.debug is set (log-level=%q); sing-box serves "+
					"/debug/pprof/* on experimental.debug.listen, and the pprof handlers "+
					"are linked into every shipped build via sing-box itself",
					tc.level)
			}

			raw, err := canonicalize(built)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(`"pprof"`)) || bytes.Contains(raw, []byte("/debug/pprof")) {
				t.Errorf("built config mentions pprof (log-level=%q)", tc.level)
			}
		})
	}
}

// V2Ray-format subscription content must NOT parse.
//
// Fork commit 9a5601d ("Remove Ray2Sing") deleted the ray2sing.Ray2SingboxOptions
// branch from parseConfigContent, together with the ray2sing submodule and its
// go.mod entry. That removal is load-bearing: it took the xray-core code path out
// of the client, and this fork only ever consumes configs the middleware issues,
// reached through a rayn://import/<token> subscription URL.
//
// Restoring the parser would be an easy-looking way to "fix" the upstream test
// this replaces (v2/profile/test TestAddByContent, quarantined as K2 in
// docs/upstream/BASELINE.md) — which is exactly why the intent is pinned here,
// offline and without the network access that test needs.
func TestV2RayFormatIsNotParsed(t *testing.T) {
	// A minimal V2Ray-style subscription body: newline-separated proxy URIs, the
	// shape ray2sing consumed. No live host is contacted; parsing fails on format
	// before anything would dial.
	const v2raySubscription = "vless://11111111-2222-3333-4444-555555555555@example.invalid:443?" +
		"security=tls&type=ws#node-a\n" +
		"trojan://password@example.invalid:443#node-b\n"

	opts := DefaultHiddifyOptions()
	shipped(opts)

	got, err := parseConfigContent(t.Context(), []byte(v2raySubscription), false, opts, false)
	if err == nil {
		t.Fatalf("V2Ray-format content parsed successfully (%d outbounds); the "+
			"ray2sing branch appears to be back. See 9a5601d — removing it took the "+
			"xray-core path out of this client.", len(got.Outbounds))
	}
	if !strings.Contains(err.Error(), "unable to determine config format") {
		t.Errorf("expected the format-detection failure, got: %v", err)
	}
}

// Every rule-set the config references must be a path under rulesets/, which is
// where the Dart extractor writes the bundled .srs files.
//
// TestNoRemoteRuleSets already forbids Type:Remote. This is the other half: a
// Local rule-set pointing outside the extractor's directory would also fail to
// load on a device, and would do so as the unhelpful "failed to start background
// core" rather than anything naming the file.
//
// data/clash.db is exempt — it is the cache file, not a rule-set source.
func TestLocalRuleSetPathsStayUnderRulesetsDir(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	for _, rs := range built.Route.RuleSet {
		path := rs.LocalOptions.Path
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "rulesets/") {
			t.Errorf("rule-set %q has path %q, which is outside rulesets/ — the Dart "+
				"extractor (lib/core/rulesets/ruleset_extractor.dart) only writes there, "+
				"so this fails on a device as \"failed to start background core\"",
				rs.Tag, path)
		}
		if strings.Contains(path, "..") {
			t.Errorf("rule-set %q path %q escapes the working directory", rs.Tag, path)
		}
	}
}
