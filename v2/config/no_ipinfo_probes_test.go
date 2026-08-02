package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/hiddify/ipinfo"
)

// No IP-geolocation probe may be resolvable.
//
// sing-box 1.14's outbound monitoring calls ipinfo.GetIpInfo through every
// outbound it tests, showing a dozen third-party endpoints the exit IP of one of
// our nodes — one of them over plain HTTP. It cannot be turned off:
// option.MonitoringOptions has no flag, ipinfo's provider lists are unexported,
// and hiddify-sing-box is not ours to edit. dns.go therefore refuses to resolve
// them, which makes the probe fail before any packet leaves.
//
// This test exists because that mitigation is invisible: nothing breaks if the
// rule is dropped, the probes simply resume, silently. It also fails if a future
// sing-box adds a provider we do not cover, since the expected set is read from
// ipinfo itself rather than hardcoded.
func TestIPInfoProbesAreNotResolvable(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)

	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	// Collect every domain any reject rule refuses, and note the first rule index
	// that could match it — order decides the outcome, and a reject sitting after
	// a route rule for the same name would never fire.
	rejected := map[string]int{}
	for i, rule := range built.DNS.Rules {
		if rule.Type != C.RuleTypeDefault && rule.Type != "" {
			continue
		}
		if rule.DefaultOptions.Action != C.RuleActionTypeReject {
			continue
		}
		for _, d := range rule.DefaultOptions.Domain {
			if _, seen := rejected[d]; !seen {
				rejected[d] = i
			}
		}
	}

	want := append([]string{}, ipinfo.GetAllIPCheckerDomainsDomains()...)
	// Not walked by that helper; see the note in dns.go.
	want = append(want, "api.myip.com", "api.country.is")

	for _, d := range want {
		idx, ok := rejected[d]
		if !ok {
			t.Errorf("IP-geolocation probe host %q is resolvable — monitoring will reach it "+
				"and disclose a node's exit IP to a third party. Add it in dns.go.", d)
			continue
		}
		if idx != 0 {
			t.Errorf("%q is rejected only at DNS rule %d; an earlier rule may route it first. "+
				"The reject must precede every routing rule.", d, idx)
		}
	}
}
