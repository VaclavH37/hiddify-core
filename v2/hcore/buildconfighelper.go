package hcore

import (
	"context"
	"encoding/json"
	"os"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/db"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func BuildConfigJson(ctx context.Context, in *StartRequest) (string, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service ")

	parsedContent, err := BuildConfig(ctx, in)
	if err != nil {
		return "", err
	}
	res, err := parsedContent.MarshalJSONContext(ctx)
	return string(res), err
}

func BuildConfig(ctx context.Context, in *StartRequest) (*option.Options, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Building Config...")

	readOpt := &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath}
	if !in.EnableRawConfig {
		// hcontent, err := json.MarshalIndent(static.HiddifyOptions, "", " ")
		// if err != nil {
		// 	return nil, err
		// }

		// Log(LogLevel_DEBUG, LogType_CORE, "Building config ", string(hcontent))
		// Log(LogLevel_DEBUG, LogType_CORE, "Building config ")
		return config.BuildConfig(ctx, static.HiddifyOptions, readOpt)
	}
	return config.ReadSingOptions(ctx, readOpt)

}

func (s *CoreService) Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	return Parse(libbox.FromContext(ctx, nil), in)
}

func Parse(ctx context.Context, in *ParseRequest) (*ParseResponse, error) {
	defer config.DeferPanicToError("parse", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})

	path := in.TempPath
	if path == "" {
		path = in.ConfigPath
	}

	config, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: in.Content, Path: path}, true, static.HiddifyOptions, false)
	if err != nil {
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_FAILED,
			Message:      err.Error(),
		}, err
	}
	if in.ConfigPath != "" {
		err = os.WriteFile(in.ConfigPath, config, 0o644)
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, err
		}
	}
	return &ParseResponse{
		ResponseCode: hcommon.ResponseCode_OK,
		Content:      string(config),
		Message:      "",
	}, err
}

func (s *CoreService) ChangeHiddifySettings(ctx context.Context, in *ChangeHiddifySettingsRequest) (*CoreInfoResponse, error) {
	return ChangeHiddifySettings(in, true)
}

func ChangeHiddifySettings(in *ChangeHiddifySettingsRequest, insert bool) (*CoreInfoResponse, error) {
	static.HiddifyOptions = config.DefaultHiddifyOptions()
	defer func() {
		switch static.HiddifyOptions.LogLevel {
		case "debug":
			static.logLevel = LogLevel_DEBUG
		case "info":
			static.logLevel = LogLevel_INFO
		case "warn":
			static.logLevel = LogLevel_WARNING
		case "error":
			static.logLevel = LogLevel_ERROR
		case "fatal":
			static.logLevel = LogLevel_FATAL
		case "trace":
			static.logLevel = LogLevel_TRACE
		default:
			static.logLevel = LogLevel_INFO
		}
		static.debug = static.debug || static.logLevel <= LogLevel_DEBUG
	}()

	if in.HiddifySettingsJson == "" {
		return &CoreInfoResponse{}, nil
	}
	if insert {
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "HiddifySettingsJson",
			Value: in.HiddifySettingsJson,
		})
	}

	err := json.Unmarshal([]byte(in.HiddifySettingsJson), static.HiddifyOptions)
	if err != nil {
		return nil, err
	}

	if static.HiddifyOptions.Warp.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.HiddifyOptions.Warp.WireguardConfigStr), &static.HiddifyOptions.Warp.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	if static.HiddifyOptions.Warp2.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.HiddifyOptions.Warp2.WireguardConfigStr), &static.HiddifyOptions.Warp2.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	return &CoreInfoResponse{}, nil
}

func (s *CoreService) GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	return GenerateConfig(libbox.FromContext(ctx, nil), in)
}

func GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (*GenerateConfigResponse, error) {
	defer config.DeferPanicToError("generateConfig", func(err error) {
		Log(LogLevel_FATAL, LogType_CONFIG, err.Error())
		StopAndAlert(MessageType_UNEXPECTED_ERROR, err.Error())
	})
	if static.HiddifyOptions == nil {
		static.HiddifyOptions = config.DefaultHiddifyOptions()
	}
	config, err := config.ParseBuildConfigBytes(ctx, static.HiddifyOptions, &config.ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}

	return &GenerateConfigResponse{
		ConfigContent: string(config),
	}, nil
}

// `removeTunnelIfNeeded` was here. It stripped the TUN inbound from a built config
// when hutils.TunAllowed() was false (non-admin Windows, non-root Linux), returning
// the removed options so a privileged helper could set the tunnel up out of process.
// It had no callers anywhere in the tree.
//
// Removed rather than wired up, because silently dropping the TUN inbound is exactly
// the failure this client was hardened against: it leaves the core with nothing
// claiming the routing table while the UI still reports Connected — the same leak
// that made `tun` the forced service mode. If the unprivileged-desktop case is ever
// handled, it must fail loudly or hand off to the tunnel service, not degrade to a
// bare loopback proxy.
