//go:build !raynconfigdump

package hcore

import (
	"context"

	"github.com/sagernet/sing-box/option"
)

// dumpBuiltConfig is a no-op in every shippable core.
//
// The plaintext-writing implementation lives in configdump.go behind
// `-tags raynconfigdump` and is not compiled into this binary at all — see the
// comment there for why a build tag rather than a runtime flag.
func dumpBuiltConfig(_ context.Context, _ *option.Options) {}
