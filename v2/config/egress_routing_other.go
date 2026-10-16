//go:build !windows

package config

// The interface-binding bypass EgressRouting describes is Windows behaviour,
// and these tables are Windows tables. Everywhere else the answer is "not
// checked", which callers treat as "nothing to report".

func EgressRoutingFor(index uint32, alias string) EgressRouting {
	return EgressRouting{}
}

func HostEgressRouting() EgressRouting {
	return EgressRouting{}
}
