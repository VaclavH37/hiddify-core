package hcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/hello"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// The foreground core's server has to survive iOS reclaiming its listening
// socket while the app is suspended. These tests cover the two halves of that:
// Setup's guard replaces a registered server that no longer accepts, and a
// server whose Serve has returned removes its own entry, so the guard is never
// handed a corpse in the first place.

// freeListen returns a loopback address nothing is listening on.
func freeListen(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// cleanupMode closes whatever server the test left registered for mode.
func cleanupMode(t *testing.T, mode SetupMode) {
	t.Cleanup(func() {
		CloseGrpcServer(mode)
		mu.Lock()
		delete(grpcSecrets, mode)
		mu.Unlock()
	})
}

func registered(mode SetupMode) *grpc.Server {
	mu.Lock()
	defer mu.Unlock()
	return grpcServer[mode]
}

func guard(t *testing.T, listen string, mode SetupMode) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	srv := grpcServer[mode]
	if srv == nil {
		t.Fatalf("no server registered for mode %d", mode)
	}
	if err := keepOrReviveLocked(srv, listen, mode); err != nil {
		t.Fatalf("keepOrReviveLocked: %v", err)
	}
}

func sayHello(t *testing.T, listen string, creds credentials.TransportCredentials, md metadata.MD) {
	t.Helper()
	conn, err := grpc.NewClient(listen, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if md != nil {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	if _, err := hello.NewHelloClient(conn).SayHello(ctx, &hello.HelloRequest{Name: "probe"}); err != nil {
		t.Fatalf("SayHello on %s: %v", listen, err)
	}
}

// stopAndRevive leaves the server the way a reclaimed socket does (registered,
// nothing accepting) and then runs Setup's guard. mu is held from the Stop to
// the guard, so the reaper cannot clear the entry first: that is the state the
// field failure was stuck in.
func stopAndRevive(t *testing.T, listen string, mode SetupMode) (old, replacement *grpc.Server) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	old = grpcServer[mode]
	if old == nil {
		t.Fatalf("no server registered for mode %d", mode)
	}
	old.Stop()
	if grpcServer[mode] != old {
		t.Fatal("entry vanished while mu was held")
	}
	if err := keepOrReviveLocked(old, listen, mode); err != nil {
		t.Fatalf("keepOrReviveLocked: %v", err)
	}
	return old, grpcServer[mode]
}

func TestGuardRevivesEntryWithNoListener(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL_INSECURE
	cleanupMode(t, mode)
	listen := freeListen(t)

	// A server that was registered but never served: nothing is listening.
	corpse := grpc.NewServer()
	mu.Lock()
	grpcServer[mode] = corpse
	mu.Unlock()

	guard(t, listen, mode)

	if got := registered(mode); got == nil || got == corpse {
		t.Fatalf("guard kept the dead server (got %p, corpse %p)", got, corpse)
	}
	sayHello(t, listen, insecure.NewCredentials(), nil)
}

func TestGuardRevivesAfterListenerDies(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL_INSECURE
	cleanupMode(t, mode)
	listen := freeListen(t)
	if _, err := StartGrpcServerByMode(listen, mode); err != nil {
		t.Fatal(err)
	}
	old, replacement := stopAndRevive(t, listen, mode)

	if replacement == nil || replacement == old {
		t.Fatalf("guard did not replace the dead server")
	}
	sayHello(t, listen, insecure.NewCredentials(), nil)

	// The old server's reaper ran after mu was released. It must have left the
	// replacement alone.
	time.Sleep(200 * time.Millisecond)
	if registered(mode) != replacement {
		t.Fatal("the dead server's reaper removed its replacement")
	}
}

func TestGuardKeepsLiveServer(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL
	cleanupMode(t, mode)
	listen := freeListen(t)
	if _, err := StartGrpcServerByMode(listen, mode); err != nil {
		t.Fatal(err)
	}
	before := registered(mode)
	cert := GetGrpcServerPublicKey()

	guard(t, listen, mode)

	if registered(mode) != before {
		t.Fatal("guard replaced a live server")
	}
	if !bytes.Equal(GetGrpcServerPublicKey(), cert) {
		t.Fatal("guard minted a certificate for a live server; the client's pin would break")
	}
}

func TestGuardMode1MintsFreshCert(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL
	cleanupMode(t, mode)
	listen := freeListen(t)
	const secret = "lifecycle-test-secret"
	mu.Lock()
	grpcSecrets[mode] = secret
	mu.Unlock()
	if _, err := StartGrpcServerByMode(listen, mode); err != nil {
		t.Fatal(err)
	}
	oldCert := GetGrpcServerPublicKey()

	stopAndRevive(t, listen, mode)

	newCert := GetGrpcServerPublicKey()
	if bytes.Equal(newCert, oldCert) {
		t.Fatal("revived secure server kept the old certificate")
	}
	// The client pins exactly the certificate it fetched after setup, and still
	// authenticates with the unchanged per-install secret.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(newCert) {
		t.Fatal("new certificate is not a PEM")
	}
	creds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	sayHello(t, listen, creds, metadata.Pairs(grpcSecretMetadataKey, secret))
}

func TestReapOnServeExit(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL_INSECURE
	cleanupMode(t, mode)
	listen := freeListen(t)
	srv, err := StartGrpcServerByMode(listen, mode)
	if err != nil {
		t.Fatal(err)
	}

	// Stopped without CloseGrpcServer, so only the reaper can clear the entry.
	srv.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for registered(mode) != nil {
		if time.Now().After(deadline) {
			t.Fatal("a server whose Serve returned is still registered")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestReapSparesReplacement(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL_INSECURE
	cleanupMode(t, mode)

	predecessor := grpc.NewServer()
	replacement := grpc.NewServer()
	mu.Lock()
	grpcServer[mode] = replacement
	mu.Unlock()

	// A listener that is already closed makes Serve return at once, with an
	// error, the way a lost socket does.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	serveAndReap(predecessor, l, mode)

	if registered(mode) != replacement {
		t.Fatal("a predecessor's exit removed its replacement")
	}
}

func TestCloseRPCThenRestartSamePort(t *testing.T) {
	mode := SetupMode_GRPC_NORMAL_INSECURE
	cleanupMode(t, mode)
	listen := freeListen(t)
	if _, err := StartGrpcServerByMode(listen, mode); err != nil {
		t.Fatal(err)
	}

	conn, err := grpc.NewClient(listen, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The server closes the connection carrying this call, so an error here is
	// expected; what matters is that the call returns at all.
	_, _ = NewCoreClient(conn).Close(ctx, &CloseRequest{Mode: mode})
	conn.Close()

	// The call can return before the handler has finished closing, so wait for
	// the entry to go rather than racing it.
	deadline := time.Now().Add(2 * time.Second)
	for registered(mode) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the Close RPC did not unregister the server")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := StartGrpcServerByMode(listen, mode); err != nil {
		t.Fatalf("could not restart on %s after a Close RPC: %v", listen, err)
	}
	sayHello(t, listen, insecure.NewCredentials(), nil)
}
