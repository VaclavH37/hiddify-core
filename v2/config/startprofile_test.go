package config

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Actually START the box against a real profile, in-process.
//
//	RAYN_START_CONFIG=".../data/debug-built-config.json" \
//	  go test -tags <full list> -ldflags=-checklinkname=0 \
//	  -run TestRealProfileStartsTheBox -v ./v2/config/
//
// Why this exists, and why it is not TestRealProfileBuildsAValidConfig:
// libbox.CheckConfigOptions calls box.New and immediately Close — it CONSTRUCTS
// a box and never starts one. Every failure that lives in a Start(stage) method
// is invisible to it. That is not hypothetical: during the sing-box 1.14 bump the
// real profile passed CheckConfigOptions cleanly while the shipped core could not
// bring a tunnel up at all, and box.log ended each attempt mid-way through
// StartStateInitialize with no error of any kind. Construction was never the
// problem, so the check that only tested construction could never have found it.
//
// Tun is OFF by default here: creating a tun device needs root, and proxy-only
// start exercises everything before the inbound stage. Set RAYN_START_TUN=1 (as
// root) to include it — if start succeeds without tun and fails with it, tun
// creation is the trigger, which is a result worth having on its own.
//
// This one really does open connections to the hub, which is why it has its own
// env var rather than riding on RAYN_CHECK_CONFIG. Same secrecy rule as the
// sibling test: nothing here prints config content, only tags and errors.
func TestRealProfileStartsTheBox(t *testing.T) {
	path := os.Getenv("RAYN_START_CONFIG")
	if path == "" {
		t.Skip("set RAYN_START_CONFIG=<path to a sing-box config json>, or " +
			"RAYN_START_CONFIG=synthetic, to run " +
			"(this test starts a real service and makes real connections)")
	}

	var in *option.Options

	// "synthetic" starts from the same generated outbound set the golden matrix
	// uses. It carries no hub address, no UUIDs and no shortIDs, so it is the
	// version of this test that can be run by anyone, pasted into an issue, or
	// put in CI. Reach for it first: if a start fault reproduces synthetically
	// then the profile is not implicated at all, which is a much stronger and
	// much cheaper result than one that needs a real subscription to see.
	if path == "synthetic" {
		in = outbounds(12)
		t.Log("using the synthetic 12-outbound fixture (no real profile involved)")
	} else {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}

		var probe struct {
			Outbounds []option.Outbound `json:"outbounds"`
			Endpoints []option.Endpoint `json:"endpoints"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("parsing %s as a sing-box config: %v", path, err)
		}

		// Same filter as TestRealProfileBuildsAValidConfig: keep only the proxy
		// outbounds, since builder.go generates the rest and feeding them back
		// would duplicate tags.
		var real []option.Outbound
		for _, o := range probe.Outbounds {
			switch o.Type {
			case "selector", "urltest", "balancer", "direct", "block", "dns":
				continue
			}
			real = append(real, o)
		}
		if len(real) == 0 {
			t.Fatal("no proxy outbounds found in the supplied config")
		}
		t.Logf("starting with %d proxy outbound(s), %d endpoint(s)",
			len(real), len(probe.Endpoints))
		in = &option.Options{Outbounds: real, Endpoints: probe.Endpoints}
	}

	stageRuleSets(t)

	// The cache-file service initialises at StartStateInitialize and opens
	// data/rayn_cache.db relative to CWD. stageRuleSets only lays out rulesets/, so
	// without this the box fails start on a missing directory — a test-environment
	// artefact that looks exactly like a config fault.
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}

	opts := DefaultHiddifyOptions()
	shipped(opts)

	withTun := os.Getenv("RAYN_START_TUN") != ""
	opts.EnableTun = withTun
	if !withTun {
		t.Log("tun DISABLED (set RAYN_START_TUN=1 as root to include it)")
	}

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: in})
	if err != nil {
		t.Fatalf("BuildConfig rejected the real outbound set: %v", err)
	}

	// The shipped profile pins warn and writes no file. Here we want everything
	// the core would say on the way up — the whole point is to see what box.log
	// could not show us.
	level := os.Getenv("RAYN_START_LOGLEVEL")
	if level == "" {
		level = "debug"
	}
	built.Log = &option.LogOptions{Level: level, Timestamp: true}

	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	defer cancel()

	instance, err := box.New(box.Options{Context: ctx, Options: *built})
	if err != nil {
		t.Fatalf("box.New failed — construction, which CheckConfigOptions would "+
			"also have caught:\n\n  %v", err)
	}
	defer instance.Close()

	// Start on its own goroutine: a Start that never returns is a distinct and
	// very real failure mode from a Start that errors, and the two need telling
	// apart. A plain call would just hang the test until the go test timeout and
	// report nothing useful about where it stopped.
	done := make(chan error, 1)
	go func() { done <- instance.Start() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("box.Start failed:\n\n  %v\n\n"+
				"This is the failure a device shows as the tunnel refusing to come up. "+
				"The stage it died in is the last one named in the log above.", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("box.Start did not return within 90s — start is HANGING, not failing. " +
			"The last log line above names the stage it stopped in.")
	}

	t.Log("box started")
}
