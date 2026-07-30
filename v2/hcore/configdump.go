//go:build raynconfigdump

package hcore

import (
	"context"
	"path/filepath"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/option"
)

// dumpBuiltConfig writes the fully built sing-box config — outbounds plus our
// routing rules, DNS servers, inbounds and balancer groups — to
// data/debug-built-config.json on every start.
//
// This file exists ONLY in a core built with `-tags raynconfigdump`. It is not
// a runtime toggle, and deliberately so: every flag that reaches the core is
// reachable by the user (the Settings → General debug switch and the log-level
// picker both feed static.debug), and the loopback gRPC channel is
// unauthenticated, so anything the core can be *asked* to do at runtime can be
// asked by any local process. A build tag is the only gate a shipped binary
// cannot be talked into opening.
//
// Restores the capability the Stage A/B/C config-hardening work relied on:
// connect, then read the built config to confirm a routing or DNS change
// actually landed. The profile config alone will not answer that — it holds the
// outbounds as the API delivered them and nothing we add around them.
//
// A core built this way MUST NOT be shipped. It writes the hub IP, the per-user
// UUIDs and the Reality shortIDs to disk in plaintext, which is precisely what
// configs/<id>.enc exists to prevent.
func dumpBuiltConfig(ctx context.Context, options *option.Options) {
	path := filepath.Join(sWorkingPath, "data/debug-built-config.json")
	Log(
		LogLevel_WARNING, LogType_CORE,
		"raynconfigdump build: writing the full built config in PLAINTEXT to ", path,
		" — this core must never be shipped",
	)
	if err := config.SaveCurrentConfig(ctx, path, *options); err != nil {
		Log(LogLevel_ERROR, LogType_CORE, "config dump failed: ", err)
	}
}
