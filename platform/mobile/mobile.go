package mobile

import (
	hcore "github.com/hiddify/hiddify-core/v2/hcore"

	// `_ "net/http/pprof"` was imported here. It started no listener by itself, but
	// its init() registers /debug/pprof/* on http.DefaultServeMux, so it only ever
	// mattered in combination with something serving that mux — which is exactly
	// what hcore.Setup used to do on localhost:6060 whenever the user enabled Debug
	// mode. That listener is now behind the raynconfigdump build tag, and this
	// import is dropped so a future http.Serve(DefaultServeMux) cannot silently
	// re-expose the handlers.
	//
	// The symbols remain in the binary regardless: the imported sing-box imports
	// net/http/pprof itself (debug_http.go, libbox/pprof.go), and that submodule is
	// not ours to edit. They are inert — nothing in a shipped build serves the mux,
	// and sing-box's own debug listener needs experimental.debug.listen, which
	// setExperimental never sets and a profile cannot inject.
	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/experimental/libbox"
)

type SetupOptions struct {
	BasePath        string
	WorkingDir      string
	TempDir         string
	Listen          string
	Secret          string
	Debug           bool
	Mode            int
	FixAndroidStack bool
}

func Setup(opt *SetupOptions, platformInterface libbox.PlatformInterface) error {
	return hcore.Setup(&hcore.SetupRequest{
		BasePath:          opt.BasePath,
		WorkingDir:        opt.WorkingDir,
		TempDir:           opt.TempDir,
		FlutterStatusPort: 0,
		Listen:            opt.Listen,
		Debug:             opt.Debug,
		Mode:              hcore.SetupMode(opt.Mode),
		Secret:            opt.Secret,
		FixAndroidStack:   opt.FixAndroidStack,
	}, platformInterface)

	// return hcore.Start(17078)
}

// func Start(configPath string, configContent string, platformInterface libbox.PlatformInterface) (*hcore.CoreInfoResponse, error) {
// 	state, err := hcore.StartWithPlatformInterface(&hcore.StartRequest{
// 		ConfigContent: configContent,
// 		ConfigPath:    configPath,
// 	}, platformInterface)
// 	return state, err
// }

func Start(configPath string, configContent string) error {
	_, err := hcore.StartService(libbox.BaseContext(nil), &hcore.StartRequest{
		ConfigPath:    configPath,
		ConfigContent: configContent,
	})
	return err
}

func Stop() error {
	_, err := hcore.Stop()
	return err
}

func GetServerPublicKey() []byte {
	return hcore.GetGrpcServerPublicKey()
}

func AddGrpcClientPublicKey(clientPublicKey []byte) error {
	return hcore.AddGrpcClientPublicKey(clientPublicKey)
}

func Close(mode int) {
	hcore.Close(hcore.SetupMode(mode))
}

func Test() string {
	return "Hello from mobile"
}

func Pause() {
	hcore.Pause()
}

func Wake() {
	hcore.Wake()
}
