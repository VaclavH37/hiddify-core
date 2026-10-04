package config

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
)

// Content guards for the rule-set FILES, as opposed to the config that loads
// them. The other rule-set tests prove the bundle opens; these prove it is safe
// to ship. They matter most once rule-sets can be refreshed at runtime from the
// Rayn mirror: its publishing pipeline runs this same test against freshly
// fetched upstream files (RAYN_RULESETS_DIR) and refuses to publish on failure.
//
// What each set is FOR comes from the built config, not from its name: a set
// referenced by a route rule whose action is "direct" decides what bypasses the
// tunnel, a set referenced by a reject rule decides what is blocked, and a set
// referenced by a DNS rule must be domain-only. So a future builder.go change
// is guarded without anyone remembering to update a list here.

const (
	// About twice today's largest file and today's total. The whole bundle is
	// held in memory by the iOS tunnel extension, which runs under a ~30 MB Go
	// limit, and a live reload briefly holds the old and new copy of a set.
	maxRuleSetFileBytes  = 1536 << 10
	maxRuleSetTotalBytes = 2 << 20
)

// Names and addresses that must always go through the tunnel and never be
// blocked. A direct-* set matching one of these would send that traffic
// outside the VPN to the local network; a block-* set matching one would break
// it for everyone with blocking on. 1.1.1.1 is also the remote DNS server, so
// routing it direct would send every remote lookup outside the tunnel.
// Private additions (MW and backend hostnames) come from RAYN_RULESET_CANARIES
// in the mirror pipeline, comma-separated, rather than living in this public
// repository.
var mustTunnelCanaries = []string{
	"google.com",
	"www.google.com",
	"youtube.com",
	"www.youtube.com",
	"gmail.com",
	"facebook.com",
	"instagram.com",
	"whatsapp.com",
	"x.com",
	"twitter.com",
	"telegram.org",
	"t.me",
	"wikipedia.org",
	"en.wikipedia.org",
	"github.com",
	"raw.githubusercontent.com",
	"openai.com",
	"chatgpt.com",
	"claude.ai",
	"netflix.com",
	"cloudflare.com",
	"raynlabs.io",
	"www.raynlabs.io",
	"api.raynlabs.io",
	"1.1.1.1",
	"1.0.0.1",
	"8.8.8.8",
	"8.8.4.4",
	"9.9.9.9",
	"2606:4700:4700::1111",
	"2001:4860:4860::8888",
}

// ruleSetRole is what the built config does with one rule-set.
type ruleSetRole struct {
	path   string
	dns    bool // referenced by a DNS rule: must be domain-only
	direct bool // routes matching traffic outside the tunnel
	block  bool // rejects matching traffic
	// Domain suffixes the direct rule carves back out of the set (the Google
	// family that geosite-cn lists but the GFW poisons). A canary under one of
	// these is still tunnelled, so it is not a failure.
	exempt []string
}

type loadedRuleSet struct {
	size  int
	plain option.PlainRuleSet
	rules []adapter.HeadlessRule
}

func TestRuleSetContentGuards(t *testing.T) {
	dir := ruleSetGuardDir(t)
	roles := ruleSetRoles(t, buildWithBlockAds(t, true))
	sets, err := loadRuleSetsForGuard(dir, roles)
	if err != nil {
		t.Fatal(err)
	}
	for _, problem := range ruleSetProblems(roles, sets, guardCanaries()) {
		t.Error(problem)
	}
}

// The guard reads each set's job off the built config. If that reading ever
// came back empty it would pass everything, so pin it to what builder.go does
// today. Changing builder.go's rule-sets means updating this list on purpose.
func TestRuleSetRolesFollowTheBuiltConfig(t *testing.T) {
	roles := ruleSetRoles(t, buildWithBlockAds(t, true))

	var direct, block, dns []string
	for tag, role := range roles {
		if role.direct {
			direct = append(direct, tag)
		}
		if role.block {
			block = append(block, tag)
		}
		if role.dns {
			dns = append(dns, tag)
		}
	}
	slices.Sort(direct)
	slices.Sort(block)
	slices.Sort(dns)

	expect := func(what string, got, want []string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s sets = %v, want %v", what, got, want)
		}
	}
	expect("direct", direct, []string{"direct-apple", "direct-private", "direct-regional-ips", "direct-regional-sites"})
	expect("block", block, []string{
		"block-ads", "block-cryptominers", "block-malware", "block-malware-ips", "block-phishing", "block-phishing-ips",
	})
	expect("DNS", dns, []string{
		"block-ads", "block-cryptominers", "block-malware", "block-phishing",
		"direct-apple", "direct-private", "direct-regional-sites",
	})
	if !slices.Contains(roles["direct-regional-sites"].exempt, "gstatic.com") {
		t.Errorf("the Google exemption was not read off the direct rule: %v", roles["direct-regional-sites"].exempt)
	}
}

// End to end on real files: the bundle with one routing set replaced by a
// file that sends google.com direct, and one in a format newer than this core
// reads. Both must be caught, or the guard is decoration.
func TestRuleSetGuardsRejectBadFiles(t *testing.T) {
	bundled := ruleSetGuardDir(t)
	roles := ruleSetRoles(t, buildWithBlockAds(t, true))

	stage := func(t *testing.T, name string, content []byte) string {
		t.Helper()
		dir := t.TempDir()
		entries, err := os.ReadDir(bundled)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".srs") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(bundled, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("a routing set that sends google.com direct", func(t *testing.T) {
		var poisoned bytes.Buffer
		err := srs.Write(&poisoned, option.PlainRuleSet{Rules: []option.HeadlessRule{{
			Type:           C.RuleTypeDefault,
			DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"qq.com", "google.com"}},
		}}}, C.RuleSetVersion1)
		if err != nil {
			t.Fatal(err)
		}
		sets, err := loadRuleSetsForGuard(stage(t, "direct-regional-sites.srs", poisoned.Bytes()), roles)
		if err != nil {
			t.Fatal(err)
		}
		problems := ruleSetProblems(roles, sets, mustTunnelCanaries)
		want := "direct-regional-sites matches google.com, so it would be routed outside the tunnel"
		if !slices.Contains(problems, want) {
			t.Errorf("problems = %q, want one to be %q", problems, want)
		}
	})

	t.Run("a set in a newer format than this core reads", func(t *testing.T) {
		newer := append([]byte("SRS"), C.RuleSetVersionCurrent+1)
		_, err := loadRuleSetsForGuard(stage(t, "block-ads.srs", newer), roles)
		if err == nil || !strings.Contains(err.Error(), "unsupported version") {
			t.Errorf("err = %v, want an unsupported-version error", err)
		}
	})
}

// ruleSetProblems is every reason the loaded sets are unsafe to ship, sorted so
// a failure reads the same on every run.
func ruleSetProblems(roles map[string]*ruleSetRole, sets map[string]loadedRuleSet, canaries []string) []string {
	var problems []string
	report := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	total := 0
	for tag, set := range sets {
		total += set.size
		if set.size > maxRuleSetFileBytes {
			report("%s is %d bytes, above the %d-byte cap", tag, set.size, maxRuleSetFileBytes)
		}

		kind, err := ruleSetKind(set.plain)
		if err != nil {
			report("%s: %v", tag, err)
		} else if roles[tag].dns && kind != "domain" {
			report("%s is referenced by a DNS rule but holds %s rules; DNS rule-sets must be "+
				"domain-only, or every lookup is resolved just to test an address against it", tag, kind)
		}
		if slices.Contains(ipPrefixes(set.plain), 0) {
			report("%s contains a /0 prefix, which matches every address", tag)
		}

		for _, canary := range canaries {
			metadata := canaryMetadata(canary)
			if !matchesAny(set.rules, &metadata) {
				continue
			}
			if roles[tag].block {
				report("%s matches %s, so it would be blocked", tag, canary)
			}
			if roles[tag].direct && !underAnySuffix(canary, roles[tag].exempt) {
				report("%s matches %s, so it would be routed outside the tunnel", tag, canary)
			}
		}
	}
	if total > maxRuleSetTotalBytes {
		report("the rule-sets total %d bytes, above the %d-byte cap", total, maxRuleSetTotalBytes)
	}
	slices.Sort(problems)
	return problems
}

func guardCanaries() []string {
	canaries := slices.Clone(mustTunnelCanaries)
	for _, extra := range strings.Split(os.Getenv("RAYN_RULESET_CANARIES"), ",") {
		if extra = strings.TrimSpace(extra); extra != "" {
			canaries = append(canaries, extra)
		}
	}
	return canaries
}

// The guard's own logic, against hand-made sets: a domain list naming a
// canary, an address set covering everything, and a set mixing kinds.
func TestRuleSetGuardHelpersCatchBadSets(t *testing.T) {
	poisoned := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"google.com"}},
	}}}
	rules := headlessRules(t, poisoned)
	metadata := canaryMetadata("www.google.com")
	if !matchesAny(rules, &metadata) {
		t.Error("a set listing google.com does not match www.google.com")
	}
	if underAnySuffix("www.google.com", []string{"gstatic.com"}) {
		t.Error("an unrelated exemption covers www.google.com")
	}
	if !underAnySuffix("c.pki.goog", []string{"pki.goog"}) || underAnySuffix("notpki.goog", []string{"pki.goog"}) {
		t.Error("suffix exemption does not follow label boundaries")
	}

	everything := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{IPCIDR: []string{"0.0.0.0/0"}},
	}}}
	if !slices.Contains(ipPrefixes(everything), 0) {
		t.Error("a 0.0.0.0/0 set is not reported as /0")
	}

	mixed := option.PlainRuleSet{Rules: []option.HeadlessRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"a.example"}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{IPCIDR: []string{"192.0.2.0/24"}}},
	}}
	if _, err := ruleSetKind(mixed); err == nil {
		t.Error("a set mixing domain and address rules is accepted")
	}

	inverted := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"a.example"}, Invert: true},
	}}}
	if _, err := ruleSetKind(inverted); err == nil {
		t.Error("an inverted rule, which matches everything but its list, is accepted")
	}

	withPort := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{Domain: []string{"a.example"}, Port: []uint16{443}},
	}}}
	if _, err := ruleSetKind(withPort); err == nil {
		t.Error("a rule with a condition other than domain or address is accepted")
	}
}

// ruleSetGuardDir is RAYN_RULESETS_DIR when set (the mirror pipeline; a missing
// directory is then a failure), else the bundled assets (skipped when absent,
// like the other bundle tests).
func ruleSetGuardDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("RAYN_RULESETS_DIR"); dir != "" {
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("RAYN_RULESETS_DIR: %v", err)
		}
		return dir
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "assets", "rulesets"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("bundled assets not available (%v)", err)
	}
	return dir
}

// ruleSetRoles reads every rule-set's role off the built config. A rule shape
// it does not understand is a failure, so a builder.go change cannot quietly
// take a set out of the guard's view.
func ruleSetRoles(t *testing.T, built *option.Options) map[string]*ruleSetRole {
	t.Helper()
	roles := map[string]*ruleSetRole{}
	for _, rs := range built.Route.RuleSet {
		if rs.Type != C.RuleSetTypeLocal {
			t.Fatalf("rule-set %q is %q, not local", rs.Tag, rs.Type)
		}
		roles[rs.Tag] = &ruleSetRole{path: rs.LocalOptions.Path}
	}
	role := func(tag string) *ruleSetRole {
		r, ok := roles[tag]
		if !ok {
			t.Fatalf("a rule references rule-set %q, which the config does not define", tag)
		}
		return r
	}

	for i, dnsRule := range built.DNS.Rules {
		if dnsRule.Type == C.RuleTypeLogical {
			t.Fatalf("DNS rule %d is logical; teach ruleSetRoles its shape", i)
		}
		for _, tag := range dnsRule.DefaultOptions.RuleSet {
			role(tag).dns = true
		}
	}

	for i, routeRule := range built.Route.Rules {
		var (
			tags   []string
			exempt []string
			action option.RuleAction
		)
		switch routeRule.Type {
		case "", C.RuleTypeDefault:
			if routeRule.DefaultOptions.Invert && len(routeRule.DefaultOptions.RuleSet) > 0 {
				t.Fatalf("route rule %d inverts a rule-set match; teach ruleSetRoles its shape", i)
			}
			tags = routeRule.DefaultOptions.RuleSet
			action = routeRule.DefaultOptions.RuleAction
		case C.RuleTypeLogical:
			logical := routeRule.LogicalOptions
			for _, sub := range logical.Rules {
				raw := sub.DefaultOptions.RawDefaultRule
				if len(raw.RuleSet) == 0 {
					continue
				}
				if logical.Mode != C.LogicalTypeAnd || logical.Invert || sub.Type == C.RuleTypeLogical || raw.Invert {
					t.Fatalf("route rule %d uses rule-sets in a shape ruleSetRoles does not know", i)
				}
				tags = append(tags, raw.RuleSet...)
			}
			if len(tags) == 0 {
				continue
			}
			for _, sub := range logical.Rules {
				raw := sub.DefaultOptions.RawDefaultRule
				if len(raw.RuleSet) > 0 {
					continue
				}
				if !raw.Invert || len(raw.DomainSuffix) == 0 {
					t.Fatalf("route rule %d pairs its rule-sets with a condition ruleSetRoles does not know", i)
				}
				exempt = append(exempt, raw.DomainSuffix...)
			}
			action = logical.RuleAction
		default:
			t.Fatalf("route rule %d has unknown type %q", i, routeRule.Type)
		}
		if len(tags) == 0 {
			continue
		}
		switch {
		case action.Action == C.RuleActionTypeReject:
			for _, tag := range tags {
				role(tag).block = true
			}
		case action.Action == C.RuleActionTypeRoute && action.RouteOptions.Outbound == OutboundDirectTag:
			for _, tag := range tags {
				r := role(tag)
				r.direct = true
				r.exempt = append(r.exempt, exempt...)
			}
		default:
			t.Fatalf("route rule %d sends rule-sets to action %q; teach ruleSetRoles what it means", i, action.Action)
		}
	}

	for tag, r := range roles {
		if !r.direct && !r.block && !r.dns {
			t.Errorf("rule-set %q is defined but no rule uses it", tag)
		}
	}
	return roles
}

// loadRuleSetsForGuard opens every set the config names, as the core would.
// srs.Read refuses a version above what this core supports, so a file in a
// newer format than the shipped core fails here rather than on a device.
func loadRuleSetsForGuard(dir string, roles map[string]*ruleSetRole) (map[string]loadedRuleSet, error) {
	sets := map[string]loadedRuleSet{}
	for tag, role := range roles {
		data, err := os.ReadFile(filepath.Join(dir, filepath.Base(role.path)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tag, err)
		}
		compat, err := srs.Read(bytes.NewReader(data), false)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tag, err)
		}
		plain, err := compat.Upgrade()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tag, err)
		}
		rules, err := buildHeadlessRules(plain)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tag, err)
		}
		sets[tag] = loadedRuleSet{size: len(data), plain: plain, rules: rules}
	}
	return sets, nil
}

func buildHeadlessRules(plain option.PlainRuleSet) ([]adapter.HeadlessRule, error) {
	rules := make([]adapter.HeadlessRule, 0, len(plain.Rules))
	for i, options := range plain.Rules {
		r, err := rule.NewHeadlessRule(context.Background(), options)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func headlessRules(t *testing.T, plain option.PlainRuleSet) []adapter.HeadlessRule {
	t.Helper()
	rules, err := buildHeadlessRules(plain)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

// ruleSetKind is "domain" or "address" when every rule in the set matches on
// that one kind of condition alone. Anything else is an error: a logical or
// inverted rule, a port, process or network condition, or a mix of kinds. Our
// sets are plain lists, and pinning their shape also keeps a live reload from
// being refused: sing-box rejects a reload that changes a DNS-referenced set's
// shape and keeps the old rules.
func ruleSetKind(plain option.PlainRuleSet) (string, error) {
	kind := ""
	for i, r := range plain.Rules {
		if r.Type == C.RuleTypeLogical {
			return "", fmt.Errorf("rule %d is a logical rule", i)
		}
		d := r.DefaultOptions
		if d.Invert {
			return "", fmt.Errorf("rule %d is inverted", i)
		}
		hasDomain := d.DomainMatcher != nil || d.AdGuardDomainMatcher != nil ||
			len(d.Domain)+len(d.DomainSuffix)+len(d.DomainKeyword)+len(d.DomainRegex)+len(d.AdGuardDomain) > 0
		hasAddress := d.IPSet != nil || len(d.IPCIDR) > 0

		rest := d
		rest.Domain, rest.DomainSuffix, rest.DomainKeyword, rest.DomainRegex = nil, nil, nil, nil
		rest.DomainMatcher, rest.AdGuardDomain, rest.AdGuardDomainMatcher = nil, nil, nil
		rest.IPCIDR, rest.IPSet = nil, nil
		if !reflect.DeepEqual(rest, option.DefaultHeadlessRule{}) {
			return "", fmt.Errorf("rule %d has a condition other than domain or address", i)
		}

		var ruleKind string
		switch {
		case hasDomain && hasAddress:
			return "", fmt.Errorf("rule %d matches on both domain and address", i)
		case hasDomain:
			ruleKind = "domain"
		case hasAddress:
			ruleKind = "address"
		default:
			return "", fmt.Errorf("rule %d has no condition", i)
		}
		if kind != "" && kind != ruleKind {
			return "", fmt.Errorf("the set mixes domain and address rules")
		}
		kind = ruleKind
	}
	if kind == "" {
		return "", fmt.Errorf("the set is empty")
	}
	return kind, nil
}

// ipPrefixes lists the prefix length of every address range in the set.
func ipPrefixes(plain option.PlainRuleSet) []int {
	var bits []int
	for _, r := range plain.Rules {
		if r.DefaultOptions.IPSet != nil {
			for _, prefix := range r.DefaultOptions.IPSet.Prefixes() {
				bits = append(bits, prefix.Bits())
			}
		}
		for _, cidr := range r.DefaultOptions.IPCIDR {
			if _, after, ok := strings.Cut(cidr, "/"); ok && after == "0" {
				bits = append(bits, 0)
			}
		}
	}
	return bits
}

// canaryMetadata is a connection to the canary as sing-box's own
// `rule-set match` command builds it: an address as the destination, anything
// else as the domain.
func canaryMetadata(canary string) adapter.InboundContext {
	var metadata adapter.InboundContext
	if address := M.ParseAddr(canary); address.IsValid() {
		metadata.Destination = M.SocksaddrFrom(address, 0)
	} else {
		metadata.Domain = canary
	}
	return metadata
}

func matchesAny(rules []adapter.HeadlessRule, metadata *adapter.InboundContext) bool {
	for _, r := range rules {
		if r.Match(metadata) {
			return true
		}
	}
	return false
}

// underAnySuffix follows sing-box's domain_suffix: the suffix itself or any
// name ending in "." plus the suffix.
func underAnySuffix(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}
