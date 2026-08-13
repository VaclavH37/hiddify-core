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
		name       string
		configured string
		ctx        context.Context
		wantOK     bool
	}{
		{
			name:       "correct secret is accepted",
			configured: good, ctx: withMD(grpcSecretMetadataKey, good), wantOK: true,
		},
		{
			name:       "wrong secret is rejected",
			configured: good, ctx: withMD(grpcSecretMetadataKey, "wrong"),
		},
		{
			name:       "absent header is rejected",
			configured: good, ctx: withMD("unrelated", "x"),
		},
		{
			name:       "no metadata at all is rejected",
			configured: good, ctx: context.Background(),
		},
		{
			// The dangerous one. A core set up without a secret must refuse
			// everything rather than accept everything -- otherwise a secure mode
			// authenticates nothing while looking like it does.
			name:       "unconfigured core rejects even a matching empty header",
			configured: "", ctx: withMD(grpcSecretMetadataKey, ""),
		},
		{
			name:       "unconfigured core rejects a populated header",
			configured: "", ctx: withMD(grpcSecretMetadataKey, good),
		},
		{
			// gRPC allows repeated keys. Accepting when any one matches would let a
			// caller brute-force by sending many values in a single call.
			name:       "duplicate headers are rejected even when one is correct",
			configured: good, ctx: withMD(grpcSecretMetadataKey, good, grpcSecretMetadataKey, "wrong"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			saved := grpcSecret
			grpcSecret = tc.configured
			defer func() { grpcSecret = saved }()

			err := requireSecret(tc.ctx)
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
