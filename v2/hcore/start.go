package hcore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/db"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	service_manager "github.com/hiddify/hiddify-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func (s *CoreService) Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return Start(static.BaseContext, in)
}

func Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func (s *CoreService) StartService(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

// saveLastStartRequest persists only the profile *name*.
//
// Rayn: the config itself is deliberately NOT persisted here. The client stores
// it encrypted at rest (configs/<id>.enc, AES-256-GCM under a per-install key
// held in the platform keystore) and hands the plaintext to the core in memory —
// over gRPC when the app is driving, or via Mobile.Start(_, configContent) when
// Android's quick-settings tile / iOS on-demand starts the core with no app
// process alive. Writing ConfigContent into this LevelDB table would put the
// hub IP, per-user UUIDs and Reality shortIDs straight back on disk in
// plaintext and silently defeat the whole scheme, and ConfigPath no longer
// names anything the core can load.
func saveLastStartRequest(in *StartRequest) error {
	if in.ConfigName == "" {
		return nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	return settings.UpdateInsert(
		&hcommon.AppSettings{
			Id:    "lastStartRequestName",
			Value: in.ConfigName,
		},
	)
}

// loadLastStartRequestIfNeeded fills in the profile name for a start request
// that already carries a config, and otherwise fails.
//
// Rayn: nothing can be restored from storage any more (see saveLastStartRequest),
// so a caller that supplies neither ConfigContent nor ConfigPath is a bug — the
// native shells must decrypt configs/<id>.enc and pass the content. Returning a
// blank StartRequest here would reach BuildConfig as os.ReadFile("") and surface
// as an unreadable "The system cannot find the file specified" instead of
// something a log reader can act on.
func loadLastStartRequestIfNeeded(in *StartRequest) (*StartRequest, error) {
	if in == nil || (in.ConfigContent == "" && in.ConfigPath == "") {
		return nil, errors.New("no config supplied: the caller must pass ConfigContent (the app decrypts configs/<id>.enc and hands it over); nothing is restorable from storage")
	}
	if in.ConfigName != "" {
		return in, nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	lastName, err := settings.Get("lastStartRequestName")
	if err != nil {
		// A missing name is cosmetic (notification title only) — never fatal.
		return in, nil
	}
	if name, ok := lastName.Value.(string); ok {
		in.ConfigName = name
	}
	return in, nil
}

func StartService(ctx context.Context, in *StartRequest) (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("startmobile", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})
	static.lock.Lock()
	defer static.lock.Unlock()

	if static.CoreState != CoreStates_STOPPED {
		// return errorWrapper(MessageType_ALREADY_STARTED, fmt.Errorf("instance already started"))
		return &CoreInfoResponse{
			CoreState:   static.CoreState,
			MessageType: MessageType_ALREADY_STARTED,
			Message:     "instance already started",
		}, nil
	}
	SetCoreStatus(CoreStates_STARTING, MessageType_EMPTY, "")

	in, err = loadLastStartRequestIfNeeded(in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}

	static.previousStartRequest = in

	if static.HiddifyOptions == nil {
		return errorWrapper(
			MessageType_ERROR_BUILDING_CONFIG,
			errors.New("HiddifyOptions not initialized"),
		)
	}

	options, err := BuildConfig(ctx, in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}
	saveLastStartRequest(in)

	Log(LogLevel_DEBUG, LogType_CORE, "Main Service pre start")
	if err := service_manager.OnMainServicePreStart(options); err != nil {
		return errorWrapper(MessageType_ERROR_EXTENSION, err)
	}
	// Rayn: two things upstream did here are deliberately gone.
	//
	// 1. `config.SaveCurrentConfig(ctx, sWorkingPath+"/data/current-config.json", …)`
	//    wrote the fully built config to disk on every start. Nothing in the
	//    core ever read it back — it was a debug artefact that left the hub IP,
	//    per-user UUIDs, Reality shortIDs and our whole routing/DNS design
	//    sitting in plaintext in %APPDATA%.
	//
	// 2. `if static.debug { Log(…, "Current Config is:\n", string(pout)) }`
	//    dumped the same content into the log stream, which reaches the in-app
	//    Logs page and the share sheet.
	//
	// Neither could simply be gated: `static.debug` is set from the Settings →
	// General debug toggle AND from the user-selectable log level (see
	// ChangeHiddifySettings), so a user picking "debug" would resurrect both in
	// a release build. That is precisely the disclosure the at-rest encryption
	// exists to prevent, so the config no longer leaves memory here at all.
	//
	// For local routing/DNS work the dump is available behind a build tag —
	// `make build-windows-libs EXTRA_TAGS=raynconfigdump`. In a shipped core
	// this call is an empty function body (configdump_disabled.go).
	dumpBuiltConfig(ctx, options)

	ctx = libbox.FromContext(ctx, static.globalPlatformInterface)
	if static.globalPlatformInterface != nil {
		platformWrapper := libbox.WrapPlatformInterface(static.globalPlatformInterface)
		service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
		// } else {
		// 	service.MustRegister[adapter.PlatformInterface](ctx, (*adapter.PlatformInterface)nil)
	}
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service with delay ?", in.DelayStart)
	if in.DelayStart {
		<-time.After(1000 * time.Millisecond)
	}
	libbox.SetMemoryLimit(C.IsIos || !in.DisableMemoryLimit)
	instance, err := NewService(ctx, *options)
	if err != nil {
		return errorWrapper(MessageType_START_SERVICE, err)
	}
	static.StartedService = instance
	if static.debug {
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-start.log"))
	}
	for inb := range options.Inbounds {
		if opts, ok := options.Inbounds[inb].Options.(option.SocksInboundOptions); ok {
			static.ListenPort = opts.ListenPort
		}
	}

	return SetCoreStatus(CoreStates_STARTED, MessageType_EMPTY, ""), nil
}
