package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// expectedBlockRuleSets maps rule-set tag -> bundled file, and must stay in sync
// with three other places: the curl targets in the root Makefile's
// fetch-rulesets, the FILES array in scripts/regen_rulesets_manifest.sh, and the
// Path literals in builder.go. This test is what makes that drift fail loudly.
var expectedBlockRuleSets = map[string]string{
	"block-ads":          "rulesets/block-ads.srs",
	"block-malware":      "rulesets/block-malware.srs",
	"block-phishing":     "rulesets/block-phishing.srs",
	"block-cryptominers": "rulesets/block-cryptominers.srs",
	"block-malware-ips":  "rulesets/block-malware-ips.srs",
	"block-phishing-ips": "rulesets/block-phishing-ips.srs",
}

func buildWithBlockAds(t *testing.T, enabled bool) *option.Options {
	t.Helper()
	opts := DefaultHiddifyOptions()
	opts.BlockAds = enabled

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{
		Options: &option.Options{
			Outbounds: []option.Outbound{
				{Type: "direct", Tag: "node-a"},
				{Type: "direct", Tag: "node-b"},
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildConfig(blockAds=%v): %v", enabled, err)
	}
	return built
}

// The headline invariant of bundling: the client must never fetch a rule-set at
// runtime. The blocklists used to be Type:Remote, pulled from a Hiddify-branded
// GitHub URL over the tunnel on first connect — the last runtime rule-set fetch
// in the product. If any rule-set ever goes back to Remote, this fails.
func TestNoRemoteRuleSets(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		built := buildWithBlockAds(t, enabled)
		for _, rs := range built.Route.RuleSet {
			if rs.Type == C.RuleSetTypeRemote {
				t.Errorf("blockAds=%v: rule-set %q is Type:Remote (URL %q); "+
					"rule-sets are bundled and must never be fetched at runtime",
					enabled, rs.Tag, rs.RemoteOptions.URL)
			}
		}
	}
}

func TestBlockRuleSetsRegisteredWhenEnabled(t *testing.T) {
	built := buildWithBlockAds(t, true)

	got := map[string]string{}
	for _, rs := range built.Route.RuleSet {
		if strings.HasPrefix(rs.Tag, "block-") {
			if rs.Type != C.RuleSetTypeLocal {
				t.Errorf("rule-set %q has type %q, want %q", rs.Tag, rs.Type, C.RuleSetTypeLocal)
			}
			got[rs.Tag] = rs.LocalOptions.Path
		}
	}

	for tag, wantPath := range expectedBlockRuleSets {
		path, ok := got[tag]
		if !ok {
			t.Errorf("rule-set %q is missing", tag)
			continue
		}
		if path != wantPath {
			t.Errorf("rule-set %q path = %q, want %q", tag, path, wantPath)
		}
	}
	for tag := range got {
		if _, ok := expectedBlockRuleSets[tag]; !ok {
			t.Errorf("unexpected block rule-set %q — update expectedBlockRuleSets, the "+
				"Makefile fetch targets and regen_rulesets_manifest.sh together", tag)
		}
	}
}

// Turning the toggle off must register nothing, so a user who does not want
// blocking pays no memory for ~1.75 MiB of matchers — and cannot be stopped from
// starting by a corrupt blocklist file.
func TestBlockRuleSetsAbsentWhenDisabled(t *testing.T) {
	built := buildWithBlockAds(t, false)
	for _, rs := range built.Route.RuleSet {
		if strings.HasPrefix(rs.Tag, "block-") {
			t.Errorf("rule-set %q registered with blockAds=false", rs.Tag)
		}
	}
}

// A geoip set in a DNS rule makes sing-box resolve every query just to obtain an
// IP to test against it — the leak already documented for direct-regional-ips on
// the China-direct path. The two IP-based blocklists belong in the route rule
// only, where a real destination address already exists.
func TestBlockDNSRuleUsesDomainSetsOnly(t *testing.T) {
	built := buildWithBlockAds(t, true)

	for i, rule := range built.DNS.Rules {
		for _, tag := range rule.DefaultOptions.RuleSet {
			if strings.HasSuffix(tag, "-ips") {
				t.Errorf("DNS rule %d references IP-based rule-set %q; DNS rules must "+
					"match on domain only", i, tag)
			}
		}
	}
}

// End-to-end: the bundled assets must actually satisfy what builder.go asks for.
// CheckConfigOptions is the same validation the shipped start path runs, and it
// opens every Type:Local rule-set — so a renamed, missing or corrupt file fails
// here rather than as "failed to start background core" on a device.
func TestBundledRuleSetFilesSatisfyConfig(t *testing.T) {
	assets, err := filepath.Abs(filepath.Join("..", "..", "..", "assets", "rulesets"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(assets)
	if err != nil {
		t.Skipf("bundled assets not available (%v)", err)
	}

	// The core resolves relative Local paths against CWD, so mirror the layout the
	// Dart extractor produces at runtime: <workingDir>/rulesets/*.srs
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

	built := buildWithBlockAds(t, true)
	if err := libbox.CheckConfigOptions(built); err != nil {
		// CheckConfigOptions stands up a real router, which needs the production
		// build tags (with_clash_api, with_utls, …). Skip rather than fail when they
		// are absent, so a bare `go test ./v2/config/` stays green — the tagged
		// invocation in CORE_BUILD.md is what actually exercises this.
		if strings.Contains(err.Error(), "is not included in this build") {
			t.Skipf("needs production build tags: %v", err)
		}
		t.Fatalf("CheckConfigOptions with bundled rule-sets: %v", err)
	}
}
