// Package raynurltest is the `lowest` ("Fastest server") group: sing-box's
// url-test group with a selection that ignores failed probes.
//
// The imported fork (hiddify-sing-box) stores a failed probe as a 65535 ms
// sentinel where upstream deletes the entry, and its url-test group's Select
// still assumes the entry is gone. Adding tolerance to 65535 wraps in uint16,
// so a dead exit is ranked as tolerance - 1 ms and wins. The fork is imported,
// not maintained here, so the group is copied into this package, corrected,
// and registered under its own config key from the contexts hcore builds.
package raynurltest

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// Type is the config key the builder emits for the `lowest` group.
//
// The running group still reports "urltest" (see New): the fork's "all
// outbounds invalid" guard and the app's ProxyType both key on the runtime
// type, and neither should learn a new name for a group that behaves the same
// on the wire. Only the emitted config says rayn_urltest.
const Type = "rayn_urltest"

// Register adds Type to registry. Idempotent: the registry overwrites.
func Register(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, Type, New)
}

// Context makes ctx able to decode and construct Type.
//
// libbox.BaseContext and include.Context install one *outbound.Registry, a
// mutex-guarded map shared by every context derived from ctx, so registering
// into it is enough and is seen everywhere downstream, including the daemon's
// own include.Context, which keeps a registry that is already present. A bare
// context gets a full include registry plus Type under both keys box.Context
// checks.
func Context(ctx context.Context) context.Context {
	if registry, ok := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry); ok && registry != nil {
		Register(registry)
		return ctx
	}
	registry := include.OutboundRegistry()
	Register(registry)
	ctx = service.ContextWith[option.OutboundOptionsRegistry](ctx, registry)
	return service.ContextWith[adapter.OutboundRegistry](ctx, registry)
}

// CheckConfigOptions is libbox.CheckConfigOptions for a config that carries
// Type. libbox runs the check on a private base context this package cannot
// seed, so the group is checked under its stock name: the options struct is
// the same, and the check validates shape, not selection.
func CheckConfigOptions(options *option.Options) error {
	if options == nil {
		return os.ErrInvalid
	}
	checked := *options
	checked.Outbounds = make([]option.Outbound, len(options.Outbounds))
	for i, out := range options.Outbounds {
		if out.Type == Type {
			out.Type = C.TypeURLTest
		}
		checked.Outbounds[i] = out
	}
	return libbox.CheckConfigOptions(&checked)
}
