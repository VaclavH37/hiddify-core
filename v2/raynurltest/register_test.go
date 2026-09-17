package raynurltest

import (
	"context"
	"strings"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// A config shaped like the builder's output: two exits and the group over
// them, under the key the builder emits.
const minimalConfig = `{
  "log": {"disabled": true},
  "outbounds": [
    {"type": "direct", "tag": "a"},
    {"type": "direct", "tag": "b"},
    {"type": "rayn_urltest", "tag": "lowest", "outbounds": ["a", "b"], "tolerance": 100}
  ]
}`

func TestContextSeedsTheSharedRegistry(t *testing.T) {
	ctx := Context(libbox.BaseContext(nil))
	ctx = Context(ctx) // idempotent

	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(minimalConfig))
	if err != nil {
		t.Fatalf("decode on a seeded context: %v", err)
	}
	if got := options.Outbounds[2].Type; got != Type {
		t.Fatalf("decoded type %q, want %q", got, Type)
	}

	// A derived context sees the same registry.
	derived, cancel := context.WithCancel(ctx)
	defer cancel()
	if _, err := json.UnmarshalExtendedContext[option.Options](derived, []byte(minimalConfig)); err != nil {
		t.Fatalf("decode on a derived context: %v", err)
	}
}

func TestBareIncludeContextDoesNotKnowTheType(t *testing.T) {
	_, err := json.UnmarshalExtendedContext[option.Options](include.Context(context.Background()), []byte(minimalConfig))
	if err == nil || !strings.Contains(err.Error(), "unknown outbound type") {
		t.Fatalf("expected an unknown-type error on an unseeded context, got %v", err)
	}
}

func TestContextSeedsABareContext(t *testing.T) {
	ctx := Context(context.Background())
	if _, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(minimalConfig)); err != nil {
		t.Fatalf("decode on a seeded bare context: %v", err)
	}
}

func TestBoxConstructsTheGroupUnderTheStockType(t *testing.T) {
	ctx, cancel := context.WithCancel(Context(libbox.BaseContext(nil)))
	defer cancel()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	defer instance.Close()

	outbound, loaded := instance.Outbound().Outbound("lowest")
	if !loaded {
		t.Fatal("the group was not constructed")
	}
	if _, isURLTest := outbound.(adapter.URLTestGroup); !isURLTest {
		t.Fatalf("%T does not satisfy adapter.URLTestGroup", outbound)
	}
	if got := outbound.Type(); got != C.TypeURLTest {
		t.Fatalf("runtime type %q, want %q: the fork's guard and the app's ProxyType key on it", got, C.TypeURLTest)
	}
	if group, ok := outbound.(adapter.OutboundGroup); !ok || len(group.All()) != 2 {
		t.Fatalf("group members: %v", outbound)
	}
}

func TestCheckConfigOptionsAcceptsTheType(t *testing.T) {
	ctx := Context(libbox.BaseContext(nil))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckConfigOptions(&options); err != nil {
		t.Fatalf("CheckConfigOptions: %v", err)
	}
	if got := options.Outbounds[2].Type; got != Type {
		t.Fatalf("the caller's options were rewritten to %q", got)
	}
	if err := libbox.CheckConfigOptions(&options); err == nil {
		t.Fatal("libbox's own check cannot know the type; if it can now, the wrapper is redundant")
	}
	if err := CheckConfigOptions(nil); err == nil {
		t.Fatal("nil options must be rejected")
	}
}
