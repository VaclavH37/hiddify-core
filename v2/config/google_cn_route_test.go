package config

import (
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// routingProbe walks a built config's own route and DNS rules with sing-box's
// matchers, against the bundled rule-sets, in the order the routers walk them.
// It answers "where does this name go", which no single rule's shape can.
type routingProbe struct {
	route      []adapter.Rule
	dns        []adapter.DNSRule
	routeFinal string
	dnsFinal   string
}

func newRoutingProbe(t *testing.T, built *option.Options) *routingProbe {
	t.Helper()
	dir := ruleSetGuardDir(t)
	logger := log.NewNOPFactory().Logger()

	sets := map[string]adapter.RuleSet{}
	for _, options := range built.Route.RuleSet {
		options.LocalOptions.Path = filepath.Join(dir, filepath.Base(options.LocalOptions.Path))
		set, err := rule.NewRuleSet(t.Context(), logger, options)
		if err != nil {
			t.Fatalf("load rule-set %s: %v", options.Tag, err)
		}
		t.Cleanup(func() { _ = set.Close() })
		sets[options.Tag] = set
	}
	ctx := service.ContextWith[adapter.Router](t.Context(), ruleSetRouter{sets: sets})

	p := &routingProbe{routeFinal: built.Route.Final, dnsFinal: built.DNS.Final}
	for i, options := range built.Route.Rules {
		r, err := rule.NewRule(ctx, logger, options, false)
		if err != nil {
			t.Fatalf("route rule %d: %v", i, err)
		}
		if err := r.Start(); err != nil {
			t.Fatalf("start route rule %d: %v", i, err)
		}
		t.Cleanup(func() { _ = r.Close() })
		p.route = append(p.route, r)
	}
	for i, options := range built.DNS.Rules {
		r, err := rule.NewDNSRule(ctx, logger, options, false, false)
		if err != nil {
			t.Fatalf("DNS rule %d: %v", i, err)
		}
		if err := r.Start(); err != nil {
			t.Fatalf("start DNS rule %d: %v", i, err)
		}
		t.Cleanup(func() { _ = r.Close() })
		p.dns = append(p.dns, r)
	}
	return p
}

// outbound is where a TLS connection from the tun, sniffed as domain, is sent.
// The destination address is outside every direct IP set, so only the name can
// send it direct.
func (p *routingProbe) outbound(domain string) string {
	metadata := adapter.InboundContext{
		Inbound:     InboundTUNTag,
		Network:     N.NetworkTCP,
		IPVersion:   4,
		Source:      M.ParseSocksaddr("172.19.0.1:50000"),
		Destination: M.ParseSocksaddr("142.251.1.1:443"),
		Protocol:    C.ProtocolTLS,
		Domain:      domain,
	}
	for _, r := range p.route {
		metadata.ResetRuleCache()
		if !r.Match(&metadata) {
			continue
		}
		switch action := r.Action().(type) {
		case *rule.RuleActionRoute:
			return action.Outbound
		case *rule.RuleActionReject:
			return "reject"
		case *rule.RuleActionHijackDNS:
			return "hijack-dns"
		}
	}
	return p.routeFinal
}

// dnsServer is the server an A query for domain is sent to, chosen the way
// dns.Router.matchDNS chooses it.
func (p *routingProbe) dnsServer(domain string) string {
	const typeA = 1
	metadata := adapter.InboundContext{Domain: domain, QueryType: typeA}
	for _, r := range p.dns {
		metadata.ResetRuleCache()
		if !r.LegacyPreMatch(&metadata) {
			continue
		}
		switch action := r.Action().(type) {
		case *rule.RuleActionDNSRoute:
			return action.Server
		case *rule.RuleActionReject:
			return "reject"
		case *rule.RuleActionPredefined:
			return "predefined"
		}
	}
	return p.dnsFinal
}

// googleapis.cn is Google's China-specific API host -- what Google Play
// services use on phones built for the Chinese market -- and it is not served
// inside China. It must leave through the tunnel with a remote lookup, while
// the .cn names Google does serve in China stay direct.
func TestGoogleChinaAPIsGoThroughTheTunnel(t *testing.T) {
	opts := DefaultHiddifyOptions()
	shipped(opts)
	if opts.Region != "cn" {
		t.Fatalf("shipped region = %q; this test is about the .cn catch-all", opts.Region)
	}
	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(2)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	p := newRoutingProbe(t, built)

	for _, tc := range []struct {
		domain   string
		outbound string
		dns      string
	}{
		{"services.googleapis.cn", p.routeFinal, DNSMultiRemoteTag},
		{"googleapis.cn", p.routeFinal, DNSMultiRemoteTag},
		// The exemption it joins, unchanged.
		{"update.googleapis.com", p.routeFinal, DNSMultiRemoteTag},
		// CN-served Google names and ordinary .cn names stay direct.
		{"www.google.cn", OutboundDirectTag, DNSCNDirectTag},
		{"www.gstatic.cn", OutboundDirectTag, DNSCNDirectTag},
		{"news.example.cn", OutboundDirectTag, DNSCNDirectTag},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			if got := p.outbound(tc.domain); got != tc.outbound {
				t.Errorf("routed to %q, want %q", got, tc.outbound)
			}
			if got := p.dnsServer(tc.domain); got != tc.dns {
				t.Errorf("resolved by %q, want %q", got, tc.dns)
			}
		})
	}
}
