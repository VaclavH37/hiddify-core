package config

import (
	"bytes"
	"strings"
	"testing"
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

			if built.DNS != nil && built.DNS.FakeIP != nil && built.DNS.FakeIP.Enabled {
				t.Errorf("dns.fakeip is enabled (EnableFakeDNS=%v); the hub runs "+
					"domainStrategy:AsIs and needs real addresses", tc.enabled)
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
