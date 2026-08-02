package config

import (
	"context"
	"os"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/protocol/group"
)

// Selecting a node while connected must both switch the selector AND reach
// whatever is streaming group state to the UI.
//
// The bug this guards: after the sing-box 1.14 bump, picking a node did nothing
// visible on Windows and Android. The core log proved the selector really did
// switch — hcore logged "select outbound" then "Trying to ping outbound", which
// is only reached once group.Selector.SelectOutbound has returned true — yet the
// app kept showing the previously active node.
//
// The reason was the notification, not the selection. 1.14 moved the group
// stream onto the outbound-monitoring broadcaster: AllProxiesInfoStream
// subscribes with monitoring.SubscribeGroup(""). Monitoring never learns about a
// manual selection by itself, because nothing inside sing-box calls
// SignalChange — it exists for embedders. So the stream never re-emitted.
//
// Two things are pinned here, because the failure needed both to be true:
//
//  1. the selector primitive still behaves (tag lookup, *group.Selector type
//     assertion, Now() moving) — an engine bump can quietly change any of them;
//  2. SignalChange("") actually wakes a SubscribeGroup("") listener, which is the
//     contract hcore.SelectOutbound now depends on to refresh the UI.
func TestSelectOutboundSwitchesAndNotifies(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real box")
	}

	stageRuleSets(t)
	// cache-file opens data/clash.db relative to CWD; see startprofile_test.go.
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}

	opts := DefaultHiddifyOptions()
	shipped(opts)
	opts.EnableTun = false

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(4)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	defer cancel()
	instance, err := box.New(box.Options{Context: ctx, Options: *built})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	defer instance.Close()

	done := make(chan error, 1)
	go func() { done <- instance.Start() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("box.Start: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("box.Start hung")
	}

	// --- 1. the selector primitive -------------------------------------------

	outboundGroup, loaded := instance.Outbound().Outbound(OutboundSelectTag)
	if !loaded {
		var tags []string
		for _, o := range instance.Outbound().Outbounds() {
			tags = append(tags, o.Tag())
		}
		t.Fatalf("selector %q not found. Outbounds present: %v", OutboundSelectTag, tags)
	}
	selector, isSelector := outboundGroup.(*group.Selector)
	if !isSelector {
		t.Fatalf("%q is %T, not *group.Selector — hcore.SelectOutbound's type assertion would fail",
			OutboundSelectTag, outboundGroup)
	}

	// --- 2. subscribe the way the UI stream does, BEFORE selecting ------------

	monitor := monitoring.Get(ctx)
	if monitor == nil {
		t.Fatal("no outbound monitoring on the context — AllProxiesInfoStream would have nothing to subscribe to")
	}
	events, err := monitor.SubscribeGroup("")
	if err != nil {
		t.Fatalf(`SubscribeGroup(""): %v`, err)
	}
	defer monitor.UnsubscribeGroup("", events)

	// Monitoring tests outbounds on its own schedule, so drain anything already
	// queued; otherwise a startup event could be mistaken for our notification.
	drain(events)

	// --- 3. select, exactly as hcore.SelectOutbound does ----------------------

	before := selector.Now()
	var target string
	for _, tag := range selector.All() {
		if tag != before {
			target = tag
			break
		}
	}
	if target == "" {
		t.Fatalf("selector has nothing to switch to; members=%v", selector.All())
	}

	if !selector.SelectOutbound(target) {
		t.Fatalf("SelectOutbound(%q) returned false; members=%v", target, selector.All())
	}
	if got := selector.Now(); got != target {
		t.Fatalf("selection did not take: Now()=%q, wanted %q (was %q)", got, target, before)
	}

	// SignalChange blocks on a capacity-1 channel, so keep it off this goroutine
	// for the same reason hcore does.
	go func() {
		_ = monitor.SignalChange("")
		_ = monitor.SignalChange(OutboundSelectTag)
	}()

	select {
	case <-events:
		t.Logf("ok  %q: %q -> %q, subscriber notified", OutboundSelectTag, before, target)
	case <-time.After(15 * time.Second):
		t.Fatalf(`selector switched to %q but no group event reached a SubscribeGroup("") `+
			`listener within 15s.

That is the shape of the original bug: the core switches, the app is never told,
and the UI keeps showing the previously active node. Check that
hcore.SelectOutbound still calls monitoring SignalChange after a successful
select, and that SignalChange("") still reaches the synthetic all-outbounds
group monitoring builds in Start().`, target)
	}
}

func drain(ch <-chan monitoring.GroupEvent) {
	for {
		select {
		case <-ch:
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}
