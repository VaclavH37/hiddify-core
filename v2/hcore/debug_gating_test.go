package hcore

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Diagnostics that would expose the hub address, per-user UUIDs, Reality
// shortIDs or a local profiling listener are compiled out of shipped builds via
// //go:build raynconfigdump. A build tag is the only gate a shipped binary
// cannot be talked into opening -- a runtime flag can be, which is exactly what
// upstream does and why these were moved.
//
// These are source-level scans. They are the cheap half; the semantic half for
// pprof is TestPprofNotLinked in pprof_linkage_test.go, which proves the package
// is not linked into a shipped-tag build at all. Both are worth having: the scan
// catches a new call site the moment it appears, in any build, without needing
// someone to run the tagged suite.
const buildTag = "//go:build raynconfigdump"

// SaveCurrentConfig writes the fully built config to disk in plaintext. Upstream
// calls it unconditionally on every start, producing data/current-config.json.
// That file names the hub, every per-user UUID and every Reality shortID.
//
// The function itself still exists (v2/config/debug.go); what must stay true is
// that nothing outside a raynconfigdump build calls it.
func TestSaveCurrentConfigOnlyCalledUnderBuildTag(t *testing.T) {
	assertCallersAreGated(t, "SaveCurrentConfig(",
		// The definition, not a call.
		map[string]bool{filepath.Join("v2", "config", "debug.go"): true},
		"writes the built config to disk in plaintext -- hub address, per-user "+
			"UUIDs and Reality shortIDs")
}

// The net/http/pprof import is not inert: its init() registers /debug/pprof/* on
// http.DefaultServeMux, so any package that later serves DefaultServeMux exposes
// a profiling endpoint. Upstream paired it with a listener on localhost:6060
// gated on a user-settable debug flag.
//
// This only covers *our* import of it. It does NOT prove pprof is absent from a
// shipped binary, and it cannot: the imported sing-box imports net/http/pprof
// itself, from three separate packages (github.com/sagernet/sing-box,
// .../experimental/libbox, and go-chi/chi/v5/middleware). Verified with
// `go list -deps`, and hiddify-sing-box is not ours to edit.
//
// So /debug/pprof/* IS registered on DefaultServeMux in every shipped build. The
// invariant that actually keeps it unreachable is the next test.
func TestPprofImportOnlyUnderBuildTag(t *testing.T) {
	assertCallersAreGated(t, `"net/http/pprof"`, nil,
		"registers /debug/pprof/* on http.DefaultServeMux, which turns any "+
			"DefaultServeMux listener into an unauthenticated profiling endpoint")
}

// The real gate on pprof reachability: nothing in a shipped build may serve
// http.DefaultServeMux.
//
// Because sing-box drags net/http/pprof in transitively, the handlers exist in
// the binary no matter what we do. They are only reachable if something serves
// the mux they are registered on. Upstream did exactly that —
// http.ListenAndServe("localhost:6060", nil) — gated on a user-settable Debug
// flag, i.e. an unauthenticated local profiling endpoint any user could switch
// on. That listener now lives in debugtools.go behind raynconfigdump.
//
// Passing nil as the handler means DefaultServeMux. That is the whole bug class,
// and it is a one-word edit away at all times, which is why it is pinned here.
func TestNothingServesDefaultServeMux(t *testing.T) {
	// http.ListenAndServe(addr, nil) / http.Serve(l, nil) /
	// http.ListenAndServeTLS(addr, cert, key, nil) — nil as the final argument.
	nilHandler := regexp.MustCompile(`http\.(ListenAndServe|ListenAndServeTLS|Serve)\([^)]*,\s*nil\s*\)`)

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"v2", "platform", "cmd"} {
		walkGoFiles(t, filepath.Join(root, dir), func(path string, src []byte) {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(src), buildTag) {
				return // debugtools.go is allowed to; that is what the tag is for.
			}
			body := stripComments(string(src))

			if m := nilHandler.FindString(body); m != "" {
				t.Errorf("%s serves DefaultServeMux via %q. sing-box registers "+
					"/debug/pprof/* on that mux transitively, so this exposes an "+
					"unauthenticated profiling endpoint. Pass an explicit mux, or move "+
					"the listener behind %q.", rel, m, buildTag)
			}
			if strings.Contains(body, "http.DefaultServeMux") {
				t.Errorf("%s references http.DefaultServeMux outside %q; /debug/pprof/* "+
					"is registered on it transitively via sing-box", rel, buildTag)
			}
		})
	}
}

// assertCallersAreGated fails for every file under v2/ and platform/ that
// contains needle without carrying the raynconfigdump build tag.
func assertCallersAreGated(t *testing.T, needle string, exempt map[string]bool, why string) {
	t.Helper()

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"v2", "platform", "cmd"} {
		walkGoFiles(t, filepath.Join(root, dir), func(path string, src []byte) {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatal(err)
			}
			if exempt[rel] {
				return
			}
			body := stripComments(string(src))
			if !strings.Contains(body, needle) {
				return
			}
			if !strings.Contains(string(src), buildTag) {
				t.Errorf("%s references %s but is not behind %q.\n%s\n"+
					"Move it into a raynconfigdump-tagged file with a !raynconfigdump "+
					"counterpart, the way v2/hcore/debugtools.go does.",
					rel, needle, buildTag, why)
			}
		})
	}
}

func walkGoFiles(t *testing.T, dir string, fn func(path string, src []byte)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// A directory that does not exist is not a failure -- `cmd` and
			// `platform` are not guaranteed to be present in every layout.
			if os.IsNotExist(err) {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(path, src)
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// stripComments removes // and /* */ comments so that a needle mentioned only in
// prose does not trip the scan. This matters here: several of these call sites
// were removed and replaced by comments explaining what used to be there and why
// it went -- v2/hcore/start.go documents the SaveCurrentConfig removal in exactly
// that way, and platform/mobile/mobile.go does the same for the pprof import.
// A scan that could not tell prose from code would fail on its own documentation.
func stripComments(src string) string {
	var out strings.Builder
	out.Grow(len(src))

	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "//"):
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				return out.String()
			}
			i += end
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			i += end + 4
		case src[i] == '"' || src[i] == '`':
			// Copy string literals verbatim; the pprof needle IS a string literal.
			quote := src[i]
			out.WriteByte(src[i])
			i++
			for i < len(src) && src[i] != quote {
				if quote == '"' && src[i] == '\\' && i+1 < len(src) {
					out.WriteByte(src[i])
					i++
				}
				out.WriteByte(src[i])
				i++
			}
			if i < len(src) {
				out.WriteByte(src[i])
				i++
			}
		default:
			out.WriteByte(src[i])
			i++
		}
	}
	return out.String()
}
