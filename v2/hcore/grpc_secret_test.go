package hcore

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// The loopback interface is not isolated between apps on any platform we ship,
// so the secret is the only thing standing between our core and any other local
// process. Each case here is a way that could be got wrong silently.
func TestRequireSecret(t *testing.T) {
	const good = "s3cret-value"

	withMD := func(pairs ...string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
	}

	cases := []struct {
		name             string
		configured       string
		enforceWhenUnset bool
		ctx              context.Context
		wantOK           bool
	}{
		{
			name:       "correct secret is accepted",
			configured: good, enforceWhenUnset: true, ctx: withMD(grpcSecretMetadataKey, good), wantOK: true,
		},
		{
			name:       "wrong secret is rejected",
			configured: good, enforceWhenUnset: true, ctx: withMD(grpcSecretMetadataKey, "wrong"),
		},
		{
			name:       "absent header is rejected",
			configured: good, enforceWhenUnset: true, ctx: withMD("unrelated", "x"),
		},
		{
			name:       "no metadata at all is rejected",
			configured: good, enforceWhenUnset: true, ctx: context.Background(),
		},
		{
			// The dangerous one. A SECURE mode set up without a secret must refuse
			// everything rather than accept everything -- otherwise it authenticates
			// nothing while looking like it does.
			name:       "unconfigured secure mode rejects even a matching empty header",
			configured: "", enforceWhenUnset: true, ctx: withMD(grpcSecretMetadataKey, ""),
		},
		{
			name:       "unconfigured secure mode rejects a populated header",
			configured: "", enforceWhenUnset: true, ctx: withMD(grpcSecretMetadataKey, good),
		},
		{
			// The background core is the deliberate exception. iOS keeps its secret
			// under AfterFirstUnlockThisDeviceOnly, so a tunnel the system starts
			// after a reboot but before the first unlock cannot read one -- and
			// refusing there would kill status and logs for a running tunnel over a
			// window the user cannot see or fix. It is not a bypass: the secret lives
			// in our own sandbox, so nothing hostile can clear it to reach this
			// branch.
			name:       "unconfigured background mode accepts, by design",
			configured: "", enforceWhenUnset: false, ctx: context.Background(), wantOK: true,
		},
		{
			// ...but once it HAS one, the exception stops applying.
			name:       "configured background mode still rejects a wrong secret",
			configured: good, enforceWhenUnset: false, ctx: withMD(grpcSecretMetadataKey, "wrong"),
		},
		{
			// gRPC allows repeated keys. Accepting when any one matches would let a
			// caller brute-force by sending many values in a single call.
			name:       "duplicate headers are rejected even when one is correct",
			configured: good, enforceWhenUnset: true, ctx: withMD(grpcSecretMetadataKey, good, grpcSecretMetadataKey, "wrong"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const mode = SetupMode_GRPC_NORMAL
			saved, had := grpcSecrets[mode]
			grpcSecrets[mode] = tc.configured
			defer func() {
				if had {
					grpcSecrets[mode] = saved
				} else {
					delete(grpcSecrets, mode)
				}
			}()

			err := requireSecret(tc.ctx, mode, tc.enforceWhenUnset)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected acceptance, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected rejection, got acceptance")
			}
			if got := status.Code(err); got != codes.Unauthenticated {
				t.Errorf("code = %v, want Unauthenticated", got)
			}
		})
	}
}

// The secret is per-MODE, and this is the test that would have caught the
// Android regression.
//
// Android's VPN service carries no `android:process`, so it runs in the app's
// own process: one Go runtime hosting the foreground core (mode 1) and the
// background core (mode 4). While both were handed the same value a single
// shared variable looked fine. The moment the background channel got its own
// rotating secret, whichever Setup ran last would have overwritten the other's,
// and every foreground call would have been rejected -- on Android only, since
// the iOS extension is a separate process.
func TestSecretsAreIsolatedPerMode(t *testing.T) {
	const fg, bg = "foreground-secret", "background-secret"

	for _, mode := range []SetupMode{SetupMode_GRPC_NORMAL, SetupMode_GRPC_BACKGROUND_INSECURE} {
		saved, had := grpcSecrets[mode]
		defer func(m SetupMode, s string, h bool) {
			if h {
				grpcSecrets[m] = s
			} else {
				delete(grpcSecrets, m)
			}
		}(mode, saved, had)
	}

	// Order matters: background is set up SECOND on both platforms.
	grpcSecrets[SetupMode_GRPC_NORMAL] = fg
	grpcSecrets[SetupMode_GRPC_BACKGROUND_INSECURE] = bg

	ctxWith := func(secret string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(grpcSecretMetadataKey, secret))
	}

	if err := requireSecret(ctxWith(fg), SetupMode_GRPC_NORMAL, true); err != nil {
		t.Fatalf("foreground rejected its own secret after background setup: %v", err)
	}
	if err := requireSecret(ctxWith(bg), SetupMode_GRPC_BACKGROUND_INSECURE, false); err != nil {
		t.Fatalf("background rejected its own secret: %v", err)
	}
	// Neither may be replayed against the other. This is the whole reason the
	// background secret is a separate value: it crosses a plaintext socket, so a
	// process that squats the port receives a copy, and it must not unlock the
	// pinned channel that carries the decrypted subscription.
	if err := requireSecret(ctxWith(bg), SetupMode_GRPC_NORMAL, true); err == nil {
		t.Fatal("background secret was accepted by the foreground core")
	}
	if err := requireSecret(ctxWith(fg), SetupMode_GRPC_BACKGROUND_INSECURE, false); err == nil {
		t.Fatal("foreground secret was accepted by the background core")
	}
}

// The metadata key travels over the wire as an HTTP/2 header. gRPC rejects keys
// containing upper-case characters outright, and the failure would appear at
// runtime on device rather than here.
func TestSecretMetadataKeyIsWireLegal(t *testing.T) {
	for _, r := range grpcSecretMetadataKey {
		if r >= 'A' && r <= 'Z' {
			t.Fatalf("metadata key %q contains upper case; gRPC will reject it", grpcSecretMetadataKey)
		}
	}
	if grpcSecretMetadataKey == "" {
		t.Fatal("metadata key is empty")
	}
}
