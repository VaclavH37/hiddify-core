package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// Validate a REAL profile's outbounds against the pinned sing-box, offline.
//
//	RAYN_CHECK_CONFIG=".../data/debug-built-config.json" \
//	  go test -tags <full list> -ldflags=-checklinkname=0 \
//	  -run TestRealProfileBuildsAValidConfig -v ./v2/config/
//
// Why this exists: every other config test in this package builds from two
// synthetic `direct` outbounds. That validates builder.go's own output but says
// nothing about the outbounds the middleware actually issues — REALITY, uTLS,
// v2ray transports — which is precisely where a sing-box bump breaks things.
// option/v2ray_transport.go changed by ~295 lines between 3a1c923e and 170d8315,
// with vless.go and tls.go alongside it. A field removed there fails at service
// start on a device while the whole test suite stays green.
//
// Takes any sing-box config JSON; only `outbounds` and `endpoints` are read from
// it. Those are fed back through BuildConfig with the shipped options, so what
// gets validated is the config this client would really emit for that profile,
// under the currently pinned sing-box.
//
// Handles secrets by not touching them: the file holds the hub address, per-user
// UUIDs and Reality shortIDs, so nothing here prints config content. Failures
// report sing-box's error and the outbound TAG only. Do not add a dump.
func TestRealProfileBuildsAValidConfig(t *testing.T) {
	path := os.Getenv("RAYN_CHECK_CONFIG")
	if path == "" {
		t.Skip("set RAYN_CHECK_CONFIG=<path to a sing-box config json> to run")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	// Only the outbound set is taken from the file. Everything else comes from
	// builder.go, so this tests the current builder against real outbounds rather
	// than replaying a config built by some older core.
	var probe struct {
		Outbounds []option.Outbound `json:"outbounds"`
		Endpoints []option.Endpoint `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("parsing %s as a sing-box config: %v\n\n"+
			"If this fails, the config itself is already unreadable by the pinned "+
			"sing-box — which is its own answer.", path, err)
	}

	// Drop the outbounds builder.go generates itself (selector, urltest, balancer,
	// direct, block, dns-out). Feeding those back in would duplicate tags.
	var real []option.Outbound
	for _, o := range probe.Outbounds {
		switch o.Type {
		case "selector", "urltest", "balancer", "direct", "block", "dns":
			continue
		}
		real = append(real, o)
	}

	t.Logf("found %d proxy outbound(s) and %d endpoint(s) in %s",
		len(real), len(probe.Endpoints), path)
	if len(real) == 0 {
		t.Fatal("no proxy outbounds found — the symptom this is meant to catch is " +
			"a config that reduces to zero outbounds, so this is a result, not a setup error")
	}

	// The core resolves Type:Local rule-set paths against CWD, so mirror the
	// layout the Dart extractor produces at runtime (<workingDir>/rulesets/*.srs).
	// Without this, router init fails on a missing block-ads.srs and masks the
	// real question — same staging as TestBundledRuleSetFilesSatisfyConfig.
	stageRuleSets(t)

	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{
		Options: &option.Options{Outbounds: real, Endpoints: probe.Endpoints},
	})
	if err != nil {
		t.Fatalf("BuildConfig rejected the real outbound set: %v", err)
	}

	// The same validation the shipped start path runs: stands up a real router,
	// DNS and every outbound, so a removed or renamed option fails here exactly as
	// it would on a device.
	if err := libbox.CheckConfigOptions(built); err != nil {
		if strings.Contains(err.Error(), "is not included in this build") {
			t.Skipf("needs the production build tags: %v", err)
		}
		t.Fatalf("CheckConfigOptions rejected the built config.\n\n"+
			"  %v\n\n"+
			"This is the failure a device would show as the core refusing to start. "+
			"Tags present in the profile are listed above; the error usually names the "+
			"offending option.", err)
	}

	for _, o := range real {
		t.Logf("  ok  outbound %-24s type=%s", o.Tag, o.Type)
	}
}

// stageRuleSets copies the bundled .srs files into a temp dir laid out the way
// the Dart extractor produces at runtime, and chdirs there. The core resolves
// Type:Local rule-set paths against CWD, so without this every config that
// registers a blocklist fails router init on a missing file — an artefact of the
// test environment that looks exactly like a real config fault.
func stageRuleSets(t *testing.T) {
	t.Helper()

	assets, err := filepath.Abs(filepath.Join("..", "..", "..", "assets", "rulesets"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(assets)
	if err != nil {
		t.Skipf("bundled rule-sets not available (%v)", err)
	}

	work := t.TempDir()
	dst := filepath.Join(work, "rulesets")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".srs") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(assets, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(work)
}
