package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// byTag returns every built outbound carrying tag.
func byTag(built *option.Options, tag string) []option.Outbound {
	var found []option.Outbound
	for _, o := range built.Outbounds {
		if o.Tag == tag {
			found = append(found, o)
		}
	}
	return found
}

func selectorMembers(t *testing.T, built *option.Options) []string {
	t.Helper()
	for _, o := range built.Outbounds {
		if o.Tag != OutboundSelectTag {
			continue
		}
		opts, ok := o.Options.(*option.SelectorOutboundOptions)
		if !ok {
			t.Fatalf("%q is %T, not *option.SelectorOutboundOptions", OutboundSelectTag, o.Options)
		}
		return opts.Outbounds
	}
	t.Fatalf("no %q group in the built config", OutboundSelectTag)
	return nil
}

// A config whose every outbound is filtered out must fail with a message, not a
// panic.
//
// setOutbounds drops groups, block/dns stubs and reserved tags, so an input made
// only of those reduces to zero tags. Indexing tags[0] then panicked; the start
// path recovered it into an alert carrying a Go stack trace, which is unreadable
// for a user and useless for support. The middleware's fail-closed body was
// exactly this shape, which is how it was found.
func TestZeroUsableOutboundsIsAnErrorNotAPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BuildConfig panicked instead of returning an error: %v", r)
		}
	}()

	opts := DefaultHiddifyOptions()
	shipped(opts)

	// Every entry here is discarded: a group, the reserved "direct" tag, and a
	// block stub. Nothing survives to become a proxy.
	in := &option.Options{Outbounds: []option.Outbound{
		{Type: C.TypeSelector, Tag: "group", Options: &option.SelectorOutboundOptions{Outbounds: []string{"block"}}},
		{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}},
		{Type: C.TypeBlock, Tag: "block", Options: &option.StubOptions{}},
	}}

	if _, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: in}); err == nil {
		t.Fatal("BuildConfig accepted a config with no usable outbound; it must refuse one")
	}
}

// A balancer arriving from a subscription is a group, not an exit.
//
// C.TypeBalancer was absent from the type switch, so an incoming balancer fell
// through to the default branch and was enrolled into tags -- becoming a member
// of the very groups this builder generates.
func TestIncomingBalancerIsNotEnrolledAsAnExit(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	in := outbounds(2)
	in.Outbounds = append(in.Outbounds, option.Outbound{
		Type:    C.TypeBalancer,
		Tag:     "incoming-balancer",
		Options: &option.BalancerOutboundOptions{Outbounds: []string{"node-a"}},
	})

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: in})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	if got := byTag(built, "incoming-balancer"); len(got) != 0 {
		t.Errorf("incoming balancer survived into the built config as %d outbound(s)", len(got))
	}
	for _, m := range selectorMembers(t, built) {
		if m == "incoming-balancer" {
			t.Errorf("incoming balancer was enrolled into the %q group: %v", OutboundSelectTag, selectorMembers(t, built))
		}
	}
}

// An input outbound tagged "balance" must not collide with the generated
// round-robin group.
//
// OutboundRoundRobinTag was missing from PredefinedOutboundTags while select and
// lowest were present, so this one tag passed through and sing-box then saw two
// outbounds sharing it.
func TestIncomingBalanceTagDoesNotCollideWithTheGeneratedGroup(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	// Two real exits, so the builder generates its own lowest/balance groups.
	in := outbounds(2)
	in.Outbounds = append(in.Outbounds, option.Outbound{
		Type:    C.TypeDirect,
		Tag:     OutboundRoundRobinTag,
		Options: &option.DirectOutboundOptions{},
	})

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: in})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	got := byTag(built, OutboundRoundRobinTag)
	if len(got) != 1 {
		t.Fatalf("expected exactly one %q outbound, got %d -- a duplicate tag fails at load",
			OutboundRoundRobinTag, len(got))
	}
	if got[0].Type != C.TypeBalancer {
		t.Errorf("the surviving %q is type %q; the generated group should have won",
			OutboundRoundRobinTag, got[0].Type)
	}
}
