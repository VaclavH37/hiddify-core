package hcore

import (
	"os"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
)

// LogInterface is installed as the global sing-box logger's PlatformWriter
// (service.go). Anything it calls must therefore not write back into that
// logger, or every message returns to WriteMessage with another "H SERVICE "
// prefix and the log grows quadratically until the disk fills.
//
// This is a source-level check rather than a behavioural one on purpose: driving
// the real loop means standing up the global logger and letting it run away,
// which is exactly the thing that fills a disk. The recursion is a property of
// which function is called, so that is what gets pinned.
//
// History: this ran unnoticed for a long time. Log()'s `level < static.logLevel`
// guard hid it in release builds, where the level is `warn` and the INFO/DEBUG
// messages that seed the loop never get through. The sing-box 1.14 bump added
// outbound monitoring, which logs through the platform writer during startup, and
// a debug build forces the level low enough to let it run: 16 GB in under a
// minute, and the service never finished starting.
func TestPlatformWriterDoesNotReenterTheLogger(t *testing.T) {
	src := readSource(t, "log_interface.go")
	body := stripComments(src)

	fn := funcBody(body, "func (h *LogInterface) WriteMessage(")
	if fn == "" {
		t.Fatal("could not find LogInterface.WriteMessage — if it was renamed, update this test rather than deleting it")
	}

	// Log() calls logLevel(), which writes to the global sing-box logger this
	// writer is attached to. PublishLog() only notifies gRPC subscribers.
	if strings.Contains(fn, "Log(") && !strings.Contains(fn, "PublishLog(") {
		t.Errorf("LogInterface.WriteMessage calls Log(), which re-enters the sing-box "+
			"logger it is a PlatformWriter for. Use PublishLog instead.\n\n%s", fn)
	}
	if !strings.Contains(fn, "PublishLog(") {
		t.Errorf("LogInterface.WriteMessage no longer calls PublishLog; if the log "+
			"plumbing changed, confirm the new path cannot reach logLevel().\n\n%s", fn)
	}
}

// PublishLog is the non-reentrant half and must stay that way.
func TestPublishLogDoesNotWriteToTheLogger(t *testing.T) {
	body := stripComments(readSource(t, "logproto.go"))

	fn := funcBody(body, "func PublishLog(")
	if fn == "" {
		t.Fatal("could not find PublishLog")
	}
	if strings.Contains(fn, "logLevel(") {
		t.Errorf("PublishLog calls logLevel(), which writes to the global sing-box "+
			"logger. That reintroduces the echo loop for every PlatformWriter "+
			"message.\n\n%s", fn)
	}
	for _, direct := range []string{"log.Debug(", "log.Info(", "log.Warn(", "log.Error(", "log.Trace("} {
		if strings.Contains(fn, direct) {
			t.Errorf("PublishLog calls %s — same problem as logLevel().\n\n%s", direct, fn)
		}
	}
}

// Guards the assumption the tests above rest on: that log.PlatformWriter is what
// LogInterface implements. If sing-box renames or restructures that, these tests
// would keep passing while guarding nothing.
func TestLogInterfaceIsStillThePlatformWriter(t *testing.T) {
	var _ log.PlatformWriter = (*LogInterface)(nil)
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// funcBody returns the text from a function's signature to its closing brace,
// matched by brace depth so a nested block does not end it early.
func funcBody(src, signature string) string {
	i := strings.Index(src, signature)
	if i < 0 {
		return ""
	}
	depth := 0
	for j := i; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[i : j+1]
			}
		}
	}
	return src[i:]
}
