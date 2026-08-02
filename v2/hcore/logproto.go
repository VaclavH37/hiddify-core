package hcore

import (
	"fmt"
	"time"

	"github.com/sagernet/sing-box/log"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func logLevel(level LogLevel, msg string) {
	switch level {
	case LogLevel_FATAL:
		log.Error(msg)
	case LogLevel_TRACE:
		log.Trace(msg)
	case LogLevel_DEBUG:
		log.Debug(msg)
	case LogLevel_INFO:
		log.Info(msg)
	case LogLevel_WARNING:
		log.Warn(msg)
	case LogLevel_ERROR:
		log.Error(msg)
	default:
		log.Debug(msg)
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
