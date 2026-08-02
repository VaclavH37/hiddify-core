package hcore

import (
	"fmt"
	"time"

	"github.com/sagernet/sing-box/log"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// consoleLogger is sing-box's process-wide std logger as it exists before any
// box has been built — the one log/export.go's init() points at os.Stderr.
//
// It is captured because sing-box 1.14 takes the global logger away from us:
// daemon/instance.go calls log.SetStdLogger(boxInstance.LogFactory().Logger())
// whenever it builds an instance, permanently repointing the package-level
// log.Debug/Info/... at the running box's log factory. Since logLevel() below
// emits through exactly those functions, every "H CORE ..." message stops
// reaching the terminal the moment the core starts and lands in box.log instead.
// Symptom: a debug run prints the startup lines, then goes silent on connect.
//
// Mirroring to this captured logger restores the pre-1.14 console behaviour
// without giving up the box.log copy. It cannot feed the log-recursion loop that
// PublishLog exists to prevent: this factory is the default stderr one and has
// no PlatformWriter attached, so nothing written here comes back round through
// LogInterface.
var consoleLogger = log.StdLogger()

func emit(l log.ContextLogger, level LogLevel, msg string) {
	switch level {
	case LogLevel_FATAL, LogLevel_ERROR:
		l.Error(msg)
	case LogLevel_TRACE:
		l.Trace(msg)
	case LogLevel_INFO:
		l.Info(msg)
	case LogLevel_WARNING:
		l.Warn(msg)
	default: // DEBUG and anything unrecognised
		l.Debug(msg)
	}
}

func logLevel(level LogLevel, msg string) {
	emit(log.StdLogger(), level, msg)

	// Only once the daemon has swapped the global logger out; before that the
	// call above already went to the console and mirroring would double-print.
	if log.StdLogger() != consoleLogger {
		emit(consoleLogger, level, msg)
	}
}
func Log(level LogLevel, typ LogType, message ...any) {
	if level < static.logLevel {
		return
	}
	// if static.debug {
	msg := fmt.Sprintf("H %v %v", typ, fmt.Sprint(message...))
	logLevel(level, msg)
	// fmt.Printf("%v %v %v\n", level, typ, fmt.Sprint(message...))
	// os.Stderr.WriteString(fmt.Sprintf("%v %v %v\n", level, typ, fmt.Sprint(message...)))
	// }

	PublishLog(level, typ, fmt.Sprint(message...))
}

// PublishLog delivers a message to the gRPC log subscribers WITHOUT writing it
// back into the sing-box logger.
//
// Anything reached FROM the sing-box log pipeline must use this rather than Log().
// Log() calls logLevel(), which writes to the global sing-box logger — the same
// logger that has LogInterface installed as its PlatformWriter (service.go). So a
// PlatformWriter that calls Log() hands the message straight back to the logger it
// just came from, gaining an "H SERVICE " prefix each pass.
//
// That loop is self-amplifying rather than merely infinite: every iteration
// re-wraps the whole previous line, so line length grows linearly and the file
// grows quadratically. Observed at 16 GB inside a minute, 45 GB shortly after,
// with the service never finishing startup because the loop starved it.
//
// Latent since long before the sing-box 1.14 bump — it needed some component to
// log through the platform writer during startup, which 1.14's outbound
// monitoring does and 1.13 did not. The `level < static.logLevel` guard in Log()
// hid it in release builds, where the level is `warn` and the INFO/DEBUG messages
// that seed the loop are dropped; a debug build forces the level down and lets it
// run.
func PublishLog(level LogLevel, typ LogType, message string) {
	if level < static.logLevel {
		return
	}
	static.logObserver.Publish(&LogMessage{
		Level:   level,
		Type:    typ,
		Time:    timestamppb.New(time.Now()),
		Message: message,
	})
}

func (s *CoreService) LogListener(req *LogRequest, stream grpc.ServerStreamingServer[LogMessage]) error {
	logSub := static.logObserver.Subscribe(1)
	defer static.logObserver.Unsubscribe(logSub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case info := <-logSub:
			if info.Level < req.Level {
				continue
			}
			stream.Send(info)
			// case <-time.After(500 * time.Millisecond):
		}
	}
}

// `dumpGoroutinesToFile` lived here, called unconditionally from stop.go and
// behind `static.debug` from start.go. Both call sites now use `dumpGoroutines`
// in goroutinedump.go, which is compiled out unless built with
// `-tags raynconfigdump`.
