package hcore

/*
#include "stdint.h"
*/

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"

	"net"
	"os"
	"strconv"
	"strings"
	sync "sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/db"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/hello"
	hutils "github.com/hiddify/hiddify-core/v2/hutils"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type CoreService struct {
	UnimplementedCoreServer
}

func Setup(params *SetupRequest, platformInterface libbox.PlatformInterface) error {
	defer config.DeferPanicToError("setup", func(err error) {
		Log(LogLevel_FATAL, LogType_CORE, err.Error())
		<-time.After(5 * time.Second)
	})
	// Compiled out unless built with -tags raynconfigdump. This served the full Go
	// pprof suite on localhost:6060 whenever the (user-settable) debug flag was on.
	startDebugHTTPServer(params.Debug)
	mu.Lock()
	defer mu.Unlock()
	if grpcServer[params.Mode] != nil {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already started")
		return nil
	}
	static.BaseContext = libbox.BaseContext(platformInterface)
	static.debug = params.Debug
	// Was plumbed from the app through platform/mobile all the way to here and
	// then read by nothing. It is the client's credential now.
	grpcSecrets[params.Mode] = params.Secret
	static.globalPlatformInterface = platformInterface
	tcpConn := true // runtime.GOOS == "windows" // TODO add TVOS
	libbox.Setup(
		&libbox.SetupOptions{
			BasePath:    params.BasePath,
			WorkingPath: params.WorkingDir,
			TempPath:    params.TempDir,
			// IsTVOS:          !tcpConn,
			FixAndroidStack: params.FixAndroidStack,
			LogMaxLines:     100,
			Debug:           params.Debug,
		})

	hutils.RedirectStderr(fmt.Sprint(params.WorkingDir, "/data/stderr", params.Mode, ".log"))

	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("libbox.Setup success %s %s %s %v", params.BasePath, params.WorkingDir, params.TempDir, tcpConn))

	sWorkingPath = params.WorkingDir
	os.Chdir(sWorkingPath)
	sTempPath = params.TempDir
	sUserID = os.Getuid()
	sGroupID = os.Getgid()

	var defaultWriter io.Writer
	if !params.Debug {
		defaultWriter = io.Discard
	}
	factory, err := log.New(
		log.Options{
			DefaultWriter: defaultWriter,
			BaseTime:      time.Now(),
			Observable:    true,
			// Options: option.LogOptions{
			// 	Disabled: false,
			// 	Level:    "trace",
			// 	Output:   "stdout",
			// },
		})
	static.CoreLogFactory = factory

	if err != nil {
		return E.Cause(err, "create logger")
	}

	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("StartGrpcServerByMode %s %d\n", params.Listen, params.Mode))
	switch params.Mode {
	case SetupMode_OLD:
		statusPropagationPort = int64(params.FlutterStatusPort)
	// case SetupMode_GRPC_BACKGROUND_INSECURE:
	default:
		_, err := StartGrpcServerByMode(params.Listen, params.Mode)
		if err != nil {
			return err
		}
	}
	settings := db.GetTable[hcommon.AppSettings]()
	val, err := settings.Get("HiddifySettingsJson")
	Log(LogLevel_DEBUG, LogType_CORE, "HiddifySettingsJson", val, err)
	if val == nil || err != nil {
		// if params.Mode == SetupMode_GRPC_BACKGROUND_INSECURE {
		_, err := ChangeHiddifySettings(&ChangeHiddifySettingsRequest{HiddifySettingsJson: ""}, false)
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, E.Cause(err, "ChangeHiddifySettings").Error())
		}
	} else {
		// settings := db.GetTable[hcommon.AppSettings]()
		_, err := ChangeHiddifySettings(&ChangeHiddifySettingsRequest{HiddifySettingsJson: val.Value.(string)}, false)
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, E.Cause(err, "ChangeHiddifySettings").Error())
		}

	}
	return InitHiddifyService()
}

func StartGrpcServer(listenAddressG string, service string) (*grpc.Server, error) {
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		log.Error("failed to listen: %v", err)
		return nil, err
	}
	s := grpc.NewServer()
	if service == "core" {
		// Setup("./tmp/", "./tmp", "./tmp", 11111, false)
		RegisterCoreServer(s, &CoreService{})
		// pb.RegisterExtensionHostServiceServer(s, &extension.ExtensionHostService{})
	} else if service == "hello" {
		// RegisterHelloServer(s, &hello.HelloService{})
	} else if service == "tunnel" {
		// RegisterTunnelServiceServer(s, &TunnelService{})
	}
	log.Info("Server listening on %s", listenAddressG)
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Error("failed to serve: %v", err)
		}
		log.Info("Server stopped")
		// cancel()
	}()
	return s, nil
}

func StartCoreGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "core")
}

func StartHelloGrpcServer(listenAddressG string) (*grpc.Server, error) {
	return StartGrpcServer(listenAddressG, "hello")
}

var (
	certpair   *hutils.CertificatePair
	grpcServer map[SetupMode]*grpc.Server = make(map[SetupMode]*grpc.Server)
	mu                                    = sync.Mutex{}

	// Secret required on every RPC, supplied by the app through
	// SetupRequest.Secret. See requireSecret.
	//
	// KEYED BY MODE, and that is load-bearing rather than tidiness. On Android
	// the VPN service has no `android:process` attribute, so it runs in the app's
	// own process — one Go runtime hosting BOTH the foreground core (mode 1) and
	// the background core (mode 4). A single package-level string meant whichever
	// Setup ran last silently overwrote the other's credential; once those two
	// stopped being the same value, every foreground call would have been
	// rejected against the background secret. iOS does not have that problem (the
	// packet-tunnel extension is a separate process) which is exactly why it
	// would have looked like an Android-only regression.
	grpcSecrets = make(map[SetupMode]string)
)

// metadata key carrying the shared secret. Lower-case: gRPC normalises header
// names, and a key with upper-case characters is rejected outright.
const grpcSecretMetadataKey = "x-rayn-secret"

// StandaloneListenAddress is where the CLI's own core listens, and where the
// `command` subcommand dials.
//
// Was 127.0.0.1:17078 — upstream Hiddify's foreground port — in three places
// that have to agree: the standalone builder, `hiddify run`, and the `command`
// client. Any Hiddify CLI on the same machine collided with it, which is the
// same defect the app was fixed for and the last place it survived.
//
// DELIBERATELY NOT 21978 OR 21979. The CLI is a separate process from the app,
// so reusing the app's foreground port would have it fight the app's own core
// for the bind — and, worse, let the CLI's insecure client attach to whichever
// won. That is precisely the class of bug the port move exists to remove; it
// would only look different because both processes are ours.
//
// Same rationale as the app's ports otherwise: below the ephemeral range
// (49152+) so the OS cannot assign it, above 1024, clear of common dev ports.
const StandaloneListenAddress = "127.0.0.1:21980"

// requireSecret rejects any call that does not present the secret this process
// was set up with.
//
// The loopback interface is not isolated between apps on any platform we ship,
// so "listening on 127.0.0.1" is not access control — any other app can connect.
// Without this, a foreign client reaching our core can drive it, and the
// symmetric hole (our client reaching a foreign core, handing it a decrypted
// subscription) is closed on the other side by the client pinning the
// certificate it fetched in-process.
//
// subtle.ConstantTimeCompare, because this runs before any other work on a
// channel an untrusted local process can open at will.
//
// enforceWhenUnset decides what an EMPTY grpcSecret means, and the two modes
// genuinely differ:
//
//   - Secure modes (1/2): true. The platform always has a secret to give — the
//     app generates it — so an empty one means the plumbing broke, and a secure
//     mode that authenticates nothing while looking like it does is worse than
//     one that refuses.
//   - Background insecure (4): false. The extension can be started on demand by
//     the system, and on iOS the keychain item is AfterFirstUnlockThisDeviceOnly
//     — a tunnel that comes up after a reboot but before the first unlock CANNOT
//     read it, so `opts.secret` is legitimately "". Refusing there would leave
//     the app unable to read status or logs from a tunnel that is running fine,
//     for a window the user cannot see or fix. Degrading to today's behaviour in
//     exactly that window is the lesser harm, and it is not a bypass: the secret
//     lives in this app's sandbox, so a hostile local process cannot clear it to
//     force this branch.
func requireSecret(ctx context.Context, mode SetupMode, enforceWhenUnset bool) error {
	secret := grpcSecrets[mode]
	if secret == "" {
		if enforceWhenUnset {
			return status.Error(codes.Unauthenticated, "core was set up without a secret")
		}
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(grpcSecretMetadataKey)
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "missing credentials")
	}
	if subtle.ConstantTimeCompare([]byte(values[0]), []byte(secret)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}
	return nil
}

func secretUnaryInterceptor(mode SetupMode, enforceWhenUnset bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := requireSecret(ctx, mode, enforceWhenUnset); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func secretStreamInterceptor(mode SetupMode, enforceWhenUnset bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := requireSecret(ss.Context(), mode, enforceWhenUnset); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// pemBody strips the armour lines and all whitespace from a PEM block, leaving
// the base64 payload. Used only to produce a fingerprint that both sides of the
// gRPC channel can compute identically.
func pemBody(pem []byte) string {
	var b strings.Builder
	for _, line := range strings.Split(string(pem), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// StartGrpcServerByMode starts a gRPC server on the specified address with mTLS.
func StartGrpcServerByMode(listenAddressG string, mode SetupMode) (*grpc.Server, error) {
	// Validate the listen address
	if !strings.Contains(listenAddressG, ":") {
		return nil, fmt.Errorf("invalid listen address (no port): %s", listenAddressG)
	}
	// Well-formedness only. The authoritative answer about whether the port is
	// usable comes from net.Listen below.
	portStr := strings.Split(listenAddressG, ":")[1]
	if _, err := strconv.ParseUint(portStr, 10, 16); err != nil {
		return nil, fmt.Errorf("failed to convert port %s to uint16: %v", portStr, err)
	}

	// THIS MUST STAY THE FIRST THING AFTER VALIDATION.
	//
	// A `hutils.IsPortInUse` probe used to run above it, and because that probe
	// is a bind test — net.Listen, then close — it returned true for a port THIS
	// PROCESS was already serving. So a second Setup call, which should be a
	// no-op returning the server below, failed with "port is already in use"
	// instead. Once anything made the client's first call fail while the server
	// was in fact up, every retry re-entered that same refusal: on iOS the retry
	// in RaynCoreService.validateConfig hit it, and profile import stayed broken
	// for the life of the process, clearing only on an app restart.
	//
	// Do not reinstate the probe. It is redundant — net.Listen returns an
	// accurate error — and it is a TOCTOU race besides: the probe binds, closes,
	// and the real listen happens afterwards against a port that may have been
	// taken in between.
	if _, exists := grpcServer[mode]; exists {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already started")
		return grpcServer[mode], nil
	}

	if mode == SetupMode_GRPC_BACKGROUND_INSECURE {
		// Authenticated but NOT encrypted, and that combination is deliberate.
		//
		// This is the core inside the VPN service (Android `:bg`) or the packet
		// tunnel extension (iOS). It serves the full CoreService, and two of those
		// RPCs matter to anyone who can reach the port: OutboundsInfo streams every
		// outbound's `host` and `port` — the hub and node addresses that
		// configs/<id>.enc exists to keep off the device in the clear — and Stop
		// silently drops the tunnel. Loopback is shared between apps on Android and
		// iOS alike, so before this any installed app could do both.
		//
		// TLS is not used here because the client cannot pin what does not exist
		// yet: this core is started by the app (or on demand by the system) long
		// after the client is built, so a certificate would have to travel
		// extension -> app through the platform store, and on Android that
		// direction is exactly the one SharedPreferences cannot do reliably across
		// processes. The secret travels app -> service, which is the direction that
		// already works.
		//
		// The cost of plaintext is that a process which squats this port before we
		// bind it receives the secret. Two things bound that: it is a DIFFERENT
		// secret from the foreground one (so it cannot be replayed against the
		// pinned, TLS-protected channel that carries the decrypted subscription),
		// and the app rotates it on every connect, so a captured value is dead by
		// the next one.
		grpcServer[mode] = grpc.NewServer(
			grpc.UnaryInterceptor(secretUnaryInterceptor(mode, false)),
			grpc.StreamInterceptor(secretStreamInterceptor(mode, false)),
		)
	} else if mode == SetupMode_GRPC_NORMAL_INSECURE {
		// Desktop only, and still unauthenticated. CoreInterfaceDesktop hardcodes
		// this mode and its client sends no secret, so enforcing here would break
		// Windows/macOS/Linux outright. Desktop is a weaker case in any event: a
		// hostile process running as the same user can already read the Drift DB,
		// where the decrypted URL sits, so loopback adds little. Left as the last
		// piece of this work.
		grpcServer[mode] = grpc.NewServer()
	} else {
		// Generated FRESH every launch, and deliberately not persisted.
		//
		// It used to be stored in the settings DB under grpc_server_public_key /
		// grpc_server_private_key and reused forever. That turned a fixed bug into
		// a permanent one: a build whose generator produced an unverifiable
		// certificate — no SAN, as this one did until the SANs were added — wrote
		// that certificate to disk, and every later build loaded it back rather
		// than generating a good one. Fixing the generator changed nothing on any
		// device that had already run the broken build; only wiping app data did.
		// That is exactly what happened on iOS, and Android escaped it only
		// because its core was current before its first secure-mode start.
		//
		// Persistence bought nothing to weigh against that. The client pins this
		// certificate after fetching it over the platform method channel in the
		// same launch, so it never needs to survive a restart, and nothing caches
		// it across one. Dropping the store also drops a dependency on a LevelDB
		// that takes a single-process lock — the app and the VPN service share a
		// working directory, so whichever starts second could not read it anyway.
		//
		// Cost is one RSA-2048 keygen per launch, at setup, once.
		var err error
		certpair, err = hutils.GenerateCertificatePair()
		if err != nil {
			Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to generate certificate pair: %v", err))
			return nil, err
		}
		// Fingerprint of what this server will present, written to STDERR on
		// purpose: stderr is redirected to data/stderr<mode>.log by Setup before
		// we get here, so it survives the gRPC channel being exactly what is
		// broken. Anything logged through the normal factory reaches the app over
		// that channel and is therefore useless for diagnosing it.
		//
		// A fingerprint of a public, per-launch, loopback-only certificate is not
		// sensitive; it exists so the pinned copy on the Dart side can be compared
		// against the served copy without guessing.
		//
		// Hashed over the base64 body rather than the PEM bytes so it matches
		// CoreInterfaceMobile._pemFingerprint, which has to ignore armour and line
		// breaks to compare a Go-encoded PEM with a Dart-re-encoded one.
		certSum := sha256.Sum256([]byte(pemBody(certpair.Certificate)))
		// certSum[:8] -> 16 hex characters, matching the substring(0, 16) the Dart
		// side takes. Truncation is fine: this distinguishes two certificates, it
		// does not authenticate one.
		fmt.Fprintf(os.Stderr, "rayn: grpc server certificate sha256=%x len=%d\n", certSum[:8], len(certpair.Certificate))
		// Load server certificate and private key
		serverCert, err := tls.X509KeyPair(certpair.Certificate, certpair.PrivateKey)
		if err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to load server certificate and key: %v\n", err))

			return nil, err
		}

		// Server-authenticated TLS, and no client certificate.
		//
		// This was RequireAndVerifyClientCert against a caCertPool that only
		// AddGrpcClientPublicKey ever populated — and that function rejected
		// certificates outright, then synthesised an x509.Certificate carrying a
		// public key and nothing else: no Raw, no Subject, no signature. Nothing
		// can chain to such a certificate, so every handshake would have failed.
		// The mode had never run.
		//
		// The client half is authenticated by the shared secret below instead,
		// which needs no certificate plumbing across four platforms and no
		// agreement between pointycastle and crypto/x509 on key encodings. What
		// TLS is doing here is the half only it can do: letting the client PIN
		// this certificate, so a client that reaches the wrong core aborts the
		// handshake rather than handing it a decrypted subscription.
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS12,
		}

		creds := credentials.NewTLS(tlsConfig)
		grpcServer[mode] = grpc.NewServer(
			grpc.Creds(creds),
			grpc.UnaryInterceptor(secretUnaryInterceptor(mode, true)),
			grpc.StreamInterceptor(secretStreamInterceptor(mode, true)),
		)
	}
	// Register your gRPC service here
	RegisterCoreServer(grpcServer[mode], &CoreService{})
	hello.RegisterHelloServer(grpcServer[mode], &hello.HelloService{})
	// Listen on the provided address
	lis, err := net.Listen("tcp", listenAddressG)
	if err != nil {
		// Undo the map entry made above. Without this the server is registered
		// but serving nothing, and the already-started guard hands that corpse
		// back to every subsequent call — a permanent connection-refused with no
		// second error to explain it. The removed IsPortInUse probe used to hide
		// this by failing before the assignment; it is a real bug either way, and
		// removing the probe is what makes it reachable.
		delete(grpcServer, mode)
		Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to listen on %s: %v\n", listenAddressG, err))
		return nil, err
	}
	Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("grpcServer started on %s\n", listenAddressG))
	log.Info("Server listening on %s", listenAddressG)

	// Run the server in a goroutine
	go func() {
		defer config.DeferPanicToError("grpcsetup", func(err error) {
			Log(LogLevel_FATAL, LogType_CORE, err.Error())
			<-time.After(5 * time.Second)
		})
		if err := grpcServer[mode].Serve(lis); err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to serve: %v\n", err))
		}
		Log(LogLevel_DEBUG, LogType_CORE, "Server stopped")
	}()

	return grpcServer[mode], nil
}

// GetGrpcServerPublicKey returns the gRPC server's public key.
// GetGrpcServerPublicKey returns the PEM certificate the client must pin, or nil
// if there is nothing to pin.
//
// nil is returned rather than dereferencing a nil certpair, which is what this
// did. certpair is only ever populated by the secure modes, so every call in an
// insecure mode — and every call made before Setup — panicked.
func GetGrpcServerPublicKey() []byte {
	mu.Lock()
	defer mu.Unlock()
	if certpair == nil {
		return nil
	}
	return certpair.Certificate
}

// AddGrpcClientPublicKey adds a client's public key to the CA pool for verification.
// Deprecated: client certificates are not used. The client is authenticated by
// the shared secret in SetupRequest.Secret; see requireSecret.
//
// Kept as a symbol because it is exported through the gomobile binding, so
// deleting it would break the Android and iOS builds before anyone read this.
// It now fails loudly instead of appearing to work: the previous implementation
// rejected certificates, then built an x509.Certificate holding a public key and
// nothing else — unusable as a CA, so every mTLS handshake would have failed.
func AddGrpcClientPublicKey(clientPublicKey []byte) error {
	return fmt.Errorf("client certificates are not supported; the client authenticates with the setup secret")
}

func CloseGrpcServer(mode SetupMode) {
	mu.Lock()
	defer mu.Unlock()
	if server, ok := grpcServer[mode]; ok && server != nil {
		server.Stop()
		delete(grpcServer, mode)
	}
}
