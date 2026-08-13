package hcore

/*
#include "stdint.h"
*/

import (
	"context"
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
	grpcSecret = params.Secret
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

	// Shared secret for the secure modes, supplied by the app through
	// SetupRequest.Secret and required on every RPC. See requireSecret.
	grpcSecret string
)

// metadata key carrying the shared secret. Lower-case: gRPC normalises header
// names, and a key with upper-case characters is rejected outright.
const grpcSecretMetadataKey = "x-rayn-secret"

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
func requireSecret(ctx context.Context) error {
	if grpcSecret == "" {
		// Setup was given no secret. Fail closed: a secure mode with no secret
		// would authenticate nothing while looking like it did.
		return status.Error(codes.Unauthenticated, "core was set up without a secret")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get(grpcSecretMetadataKey)
	if len(values) != 1 {
		return status.Error(codes.Unauthenticated, "missing credentials")
	}
	if subtle.ConstantTimeCompare([]byte(values[0]), []byte(grpcSecret)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid credentials")
	}
	return nil
}

func secretUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := requireSecret(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func secretStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := requireSecret(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
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

	if mode == SetupMode_GRPC_BACKGROUND_INSECURE || mode == SetupMode_GRPC_NORMAL_INSECURE {
		grpcServer[mode] = grpc.NewServer()
	} else {
		table := db.GetTable[hcommon.AppSettings]()
		Log(LogLevel_DEBUG, LogType_CORE, table)
		grpcServerPrivateKey, err := table.Get("grpc_server_private_key")
		grpcServerPublicKey, err2 := table.Get("grpc_server_public_key")
		if err != nil || err2 != nil {
			Log(LogLevel_DEBUG, LogType_CORE, fmt.Sprintf("failed to get grpc_server_private_key and grpc_server_public_key from database: %v %v\n", err, err2))
			certpair, err = hutils.GenerateCertificatePair()
			if err != nil {
				Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf("failed to generate certificate pair: %v", err))

				return nil, err
			}
			table.UpdateInsert(
				&hcommon.AppSettings{Id: "grpc_server_public_key", Value: certpair.Certificate},
				&hcommon.AppSettings{Id: "grpc_server_private_key", Value: certpair.PrivateKey},
			)
		} else {
			certpair = &hutils.CertificatePair{
				Certificate: grpcServerPublicKey.Value.([]byte),
				PrivateKey:  grpcServerPrivateKey.Value.([]byte),
			}
		}
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
			grpc.UnaryInterceptor(secretUnaryInterceptor),
			grpc.StreamInterceptor(secretStreamInterceptor),
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
