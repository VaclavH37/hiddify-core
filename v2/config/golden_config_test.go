package config

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
)

// -update rewrites the golden files instead of comparing against them.
//
//	go test -tags <full list> ./v2/config/ -run TestGoldenConfig -update
//
// Regenerating is a deliberate act: the resulting diff is the review artifact
// for whatever change made it necessary. Never regenerate to make a red test
// green without reading the diff first.
var updateGolden = flag.Bool("update", false, "rewrite testdata/golden/*.json")

// Volatile values that legitimately differ run to run and carry no design
// signal. Redacted rather than dropped, so their presence or absence is still
// part of the golden.
//
// clash-api secret: builder.go generates a fresh 16-char random string whenever
// the Clash API is enabled without one.
var volatileKeys = map[string]bool{
	"secret": true,
}

// goldenFixtures is the matrix. Each entry is a scenario whose generated
// sing-box config is pinned byte-for-byte.
//
// The point is not that any particular byte is correct — it is that a change to
// builder.go, dns.go or the defaults cannot alter the shipped config without a
// human reading the diff. That is the gap this closes: before this test the only
// config assertions were the four structural ones in block_rulesets_test.go and
// ntp_removal_test.go, so an upstream commit could rewrite DNS server selection,
// route ordering, sniffing or domain_strategy with every test still green.
var goldenFixtures = []struct {
	name string
	opts func(*HiddifyOptions)
	in   *option.Options
}{
	// THE important row: what a release build actually emits.
	{
		name: "shipped",
		opts: shipped,
		in:   outbounds(2),
	},
	// The user turns blocking off. Pins that the toggle removes the six
	// blocklists and touches nothing else.
	{
		name: "shipped-blockads-off",
		opts: with(func(o *HiddifyOptions) { o.BlockAds = false }),
		in:   outbounds(2),
	},
	// A debug build. Pins exactly what debug changes, so debug-only wiring
	// leaking into the release path shows up as a diff on "shipped" instead.
	{
		name: "shipped-debug",
		opts: with(func(o *HiddifyOptions) { o.LogLevel = "debug"; o.LogFile = "data/box.log" }),
		in:   outbounds(2),
	},
	// QUIC suppression off. Backend-overridable per subscription, so both
	// positions are shipped configurations and both are pinned.
	{
		name: "shipped-blockquic-off",
		opts: with(func(o *HiddifyOptions) { o.BlockQuic = false }),
		in:   outbounds(2),
	},
	// A realistic exit set. Exercises selector / url-test / balancer group
	// construction, which two outbounds do not.
	{
		name: "shipped-many-outbounds",
		opts: shipped,
		in:   outbounds(12),
	},
	// Bare DefaultHiddifyOptions, which is NOT what ships — see shipped() below.
	// Kept so that an upstream change to the Go-side defaults is visible on its
	// own, separately from a change to what the client sends.
	{
		name: "go-defaults",
		opts: func(o *HiddifyOptions) {},
		in:   outbounds(2),
	},
}

// shipped mirrors the payload the Flutter layer sends in a release build.
//
// It is applied on top of DefaultHiddifyOptions() because that is exactly how
// the real path works: the client's settings are unmarshalled *over* the Go
// defaults, so any field the client omits keeps the Go default. BalancerStrategy
// is the live example — the Dart payload deliberately omits it and relies on the
// default being round-robin.
//
// SOURCE OF TRUTH: lib/features/settings/data/config_option_repository.dart,
// provider `singboxConfigOptions`. This is a hand transcription and will rot
// silently if only one side changes, which is why the Dart side pins the same
// values in test/design/. Change both together.
//
// Why this fixture exists at all: DefaultHiddifyOptions() is not the shipped
// configuration and differs from it in ways that matter — the Go defaults have
// the tun OFF, TUNStack "mixed", BlockAds off, DirectPort 12337 and a bare
// "1.1.1.1" resolver, where the client ships tun ON, gvisor, blocking on,
// DirectPort 0 and DoH. A golden matrix built only on Go defaults would pin a
// config the product never emits.
func shipped(o *HiddifyOptions) {
	o.Region = "cn"
	o.BlockAds = true
	o.EnableFullConfig = false

	// Release pins warn and writes no log file; see the LogLevel comment in
	// config_option_repository.dart for why anything below warn turns the log
	// into a browsing history.
	o.LogLevel = "warn"
	o.LogFile = ""

	o.RemoteDnsAddress = "https://1.1.1.1/dns-query"
	o.RemoteDnsDomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	o.DirectDnsAddress = "https://dns.alidns.com/dns-query"
	o.DirectDnsDomainStrategy = option.DomainStrategy(dns.DomainStrategyUseIPv4)
	o.IndependentDNSCache = true
	o.EnableFakeDNS = false

	o.EnableTun = true
	o.SetSystemProxy = false
	o.MixedPort = 12334
	o.TProxyPort = 12335
	o.RedirectPort = 12336
	o.DirectPort = 0 // 0 disables the vestigial dns-in listener entirely
	o.MTU = 9000
	o.StrictRoute = true
	o.TUNStack = "gvisor"

	o.ConnectionTestUrl = "https://cp.cloudflare.com"
	// The real value is drawn per session from [20, 40] minutes to de-synchronise
	// url-test bursts across installs. Pinned here because a golden cannot encode
	// a random value, and because what this fixture is for is the config's shape.
	o.URLTestInterval = DurationInSeconds(1800)
	o.URLTestTolerance = 100

	o.BypassLAN = false
	o.AllowConnectionFromLAN = false
	o.BlockQuic = true

	o.EnableClashApi = true
	o.ClashApiPort = 16756
}

func with(extra func(*HiddifyOptions)) func(*HiddifyOptions) {
	return func(o *HiddifyOptions) {
		shipped(o)
		extra(o)
	}
}

func outbounds(n int) *option.Options {
	list := make([]option.Outbound, 0, n)
	for i := 0; i < n; i++ {
		list = append(list, option.Outbound{
			Type: "direct",
			Tag:  "node-" + string(rune('a'+i)),
			// Non-nil, because sing-box's registry marshaller rejects an
			// outbound whose Options are nil ("expected json object start, but
			// starts with nil"). A profile off the wire always carries options,
			// so a nil here is a fixture artefact, not a shape worth pinning.
			Options: &option.DirectOutboundOptions{},
		})
	}
	return &option.Options{Outbounds: list}
}

func TestGoldenConfig(t *testing.T) {
	for _, fx := range goldenFixtures {
		t.Run(fx.name, func(t *testing.T) {
			opts := DefaultHiddifyOptions()
			fx.opts(opts)

			built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: fx.in})
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}

			got, err := canonicalize(built)
			if err != nil {
				t.Fatalf("canonicalize: %v", err)
			}

			path := filepath.Join("testdata", "golden", fx.name+".json")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s (%d bytes)", path, len(got))
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading golden: %v\nrun with -update to create it", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("generated config differs from %s.\n"+
					"If the change is intended, rerun with -update and put the resulting "+
					"diff in the review.\n\n%s", path, firstDiff(want, got))
			}
		})
	}
}

// BuildConfig must be a pure function of its inputs, otherwise the goldens flake
// and the whole gate is worthless.
//
// Repeated deliberately. The variance this was written to catch came from
// iterating a Go map to build a DNS rule's Domain list (dns.go), and Go
// randomizes map iteration per loop — with two elements a single extra build
// only catches it half the time. It did in fact pass by luck before the fix
// landed, while TestGoldenConfig failed on two of five fixtures. 32 rounds puts
// a two-element permutation beyond plausible luck, and anything wider is caught
// almost immediately.
func TestBuildConfigIsDeterministic(t *testing.T) {
	const rounds = 32

	reference, err := canonicalizeBuild(t)
	if err != nil {
		t.Fatalf("BuildConfig (reference): %v", err)
	}
	for i := 1; i < rounds; i++ {
		got, err := canonicalizeBuild(t)
		if err != nil {
			t.Fatalf("BuildConfig (round %d): %v", i, err)
		}
		if !bytes.Equal(reference, got) {
			t.Fatalf("build %d of identical input differs from build 0; a golden "+
				"test cannot work until this is fixed. Either the source of variance "+
				"belongs in volatileKeys, or it is a bug.\n\n%s",
				i, firstDiff(reference, got))
		}
	}
}

func canonicalizeBuild(t *testing.T) ([]byte, error) {
	t.Helper()
	opts := DefaultHiddifyOptions()
	shipped(opts)
	built, err := BuildConfig(t.Context(), opts, &ReadOptions{Options: outbounds(4)})
	if err != nil {
		return nil, err
	}
	return canonicalize(built)
}

// canonicalize renders a built config as stable, comparable bytes: through
// encoding/json (which sorts map keys) with volatile values redacted.
//
// It MUST marshal through MarshalJSONContext with a registry-bearing context.
// sing-box resolves the concrete options of every inbound, outbound and DNS
// server through a registry looked up on the context, so a plain json.Marshal
// silently reduces each of them to {tag, type} and drops everything else.
//
// This was not a theoretical gap. Under plain json.Marshal these goldens pinned
// the route and DNS *rules* but none of the protocol options — no tun MTU or
// stack, no DNS server addresses, and no dialer detours. That is precisely the
// field that broke the tunnel on the sing-box 1.14 bump (dns.go's detour onto an
// empty direct outbound), and the matrix could not see it: the fixtures stayed
// byte-identical across the change that broke the client. Marshal without the
// context and this test quietly stops testing most of the config.
func canonicalize(o *option.Options) ([]byte, error) {
	raw, err := o.MarshalJSONContext(include.Context(context.Background()))
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	redact(tree)
	out, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func redact(node any) {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if volatileKeys[k] {
				v[k] = "<redacted>"
				continue
			}
			redact(v[k])
		}
	case []any:
		for _, item := range v {
			redact(item)
		}
	}
}

// firstDiff reports the first differing line with a little context, because a
// whole-config dump is unreadable in test output.
func firstDiff(want, got []byte) string {
	w := bytes.Split(want, []byte{'\n'})
	g := bytes.Split(got, []byte{'\n'})
	for i := 0; i < len(w) || i < len(g); i++ {
		var lw, lg []byte
		if i < len(w) {
			lw = w[i]
		}
		if i < len(g) {
			lg = g[i]
		}
		if !bytes.Equal(lw, lg) {
			var b bytes.Buffer
			for j := max(0, i-3); j < i; j++ {
				if j < len(w) {
					b.WriteString("  " + string(w[j]) + "\n")
				}
			}
			b.WriteString("- want: " + string(lw) + "\n")
			b.WriteString("+ got:  " + string(lg) + "\n")
			return b.String()
		}
	}
	return "(files differ only in length)"
}
