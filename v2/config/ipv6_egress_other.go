//go:build !windows

package config

// hostEgressRoutes reports nothing outside Windows, so hostEgressIPv6 is true
// there. The loop it guards against needs sing's ignored IPV6_UNICAST_IF,
// which is Windows code; elsewhere the tun's IPv6 claim is unchanged.
func hostEgressRoutes() ([]egressRoute, error) {
	return nil, nil
}
