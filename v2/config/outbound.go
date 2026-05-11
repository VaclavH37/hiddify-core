package config

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type outboundMap map[string]interface{}

func patchOutboundMux(base option.Outbound, configOpt HiddifyOptions, obj outboundMap) outboundMap {
	if configOpt.Mux.Enable {
		multiplex := option.OutboundMultiplexOptions{
			Enabled:    true,
			Padding:    configOpt.Mux.Padding,
			MaxStreams: configOpt.Mux.MaxStreams,
			Protocol:   configOpt.Mux.Protocol,
		}
		obj["multiplex"] = multiplex
		// } else {
		// 	delete(obj, "multiplex")
	}
	return obj
}

func patchOutboundTLSTricks(base option.Outbound, configOpt HiddifyOptions) option.Outbound {
	if base.Type == C.TypeSelector || base.Type == C.TypeURLTest || base.Type == C.TypeBlock || base.Type == C.TypeDNS {
		return base
	}
	if isOutboundReality(base) {
		return base
	}

	var tls *option.OutboundTLSOptions
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls = tlsopt.TakeOutboundTLSOptions()
	}

	var transport *option.V2RayTransportOptions
	if opts, ok := base.Options.(option.VLESSOutboundOptions); ok {
		transport = opts.Transport
	} else if opts, ok := base.Options.(option.TrojanOutboundOptions); ok {
		transport = opts.Transport
	} else if opts, ok := base.Options.(option.VMessOutboundOptions); ok {
		transport = opts.Transport
	}

	if base.Type == C.TypeDirect {
		return patchOutboundFragment(base, configOpt)
	}

	if tls == nil || !tls.Enabled || transport == nil {
		return base
	}

	if transport.Type != C.V2RayTransportTypeWebsocket && transport.Type != C.V2RayTransportTypeGRPC && transport.Type != C.V2RayTransportTypeHTTPUpgrade {
		return base
	}

	base = patchOutboundFragment(base, configOpt)

	if tls.TLSTricks == nil {
		tls.TLSTricks = &option.TLSTricksOptions{}
	}
	tls.TLSTricks.MixedCaseSNI = tls.TLSTricks.MixedCaseSNI || configOpt.TLSTricks.MixedSNICase

	if false && configOpt.TLSTricks.EnablePadding {
		tls.TLSTricks.PaddingMode = "random"
		tls.TLSTricks.PaddingSize = configOpt.TLSTricks.PaddingSize
		tls.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "custom",
		}
		// fmt.Printf("--------------------%+v----%+v", tlsTricks.PaddingSize, configOpt)

	}

	// if tlsTricks.MixedCaseSNI || tlsTricks.PaddingMode != "" {
	// 	// } else {
	// 	// 	tls["tls_tricks"] = nil
	// }
	// fmt.Printf("-------%+v------------- ", tlsTricks)

	return base
}

func patchOutboundFragment(base option.Outbound, configOpt HiddifyOptions) option.Outbound {
	if configOpt.TLSTricks.EnableFragment {
		if opts, ok := base.Options.(option.DialerOptionsWrapper); ok {
			dialer := opts.TakeDialerOptions()
			dialer.TCPFastOpen = false
			dialer.TLSFragment = option.TLSFragmentOptions{
				Enabled: configOpt.TLSTricks.EnableFragment,
				Size:    configOpt.TLSTricks.FragmentSize,
				Sleep:   configOpt.TLSTricks.FragmentSleep,
			}
			opts.ReplaceDialerOptions(dialer)
		}

	}

	return base
}

func isOutboundReality(base option.Outbound) bool {
	// this function checks reality status ONLY FOR VLESS.
	// Some other protocols can also use reality, but it's discouraged as stated in the reality document
	if base.Type != C.TypeVLESS {
		return false
	}
	var tls *option.OutboundTLSOptions
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls = tlsopt.TakeOutboundTLSOptions()
	}

	if tls == nil || !tls.Enabled {
		return false
	}
	if tls.Reality == nil {
		return false
	}

	return tls.Reality.Enabled
}

func patchEndpoint(base *option.Endpoint, configOpt HiddifyOptions, staticIPs *map[string][]string) (*option.Endpoint, error) {
	formatErr := func(err error) error {
		return fmt.Errorf("error patching outbound[%s][%s]: %w", base.Tag, base.Type, err)
	}
	err := patchWarp(base, &configOpt, true, *staticIPs)
	if err != nil {
		return nil, formatErr(err)
	}
	return base, nil
}
func patchOutbound(base option.Outbound, configOpt HiddifyOptions, staticIPs *map[string][]string) (*option.Outbound, error) {

	base = patchOutboundTLSTricks(base, configOpt)

	return &base, nil
}

