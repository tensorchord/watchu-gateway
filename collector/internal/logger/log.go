package logger

import (
	"time"

	"github.com/phuslu/log"
)

func SetUpLogger(debug bool) {
	if debug {
		log.DefaultLogger = log.Logger{
			Level:      log.DebugLevel,
			Caller:     1,
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				QuoteString:    true,
				EndWithMessage: true,
			},
		}
	} else {
		log.DefaultLogger = log.Logger{
			Level:        log.InfoLevel,
			TimeField:    "timestamp",
			TimeLocation: time.UTC,
		}
	}
}
