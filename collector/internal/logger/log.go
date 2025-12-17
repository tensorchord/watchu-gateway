package logger

import (
	"os"

	"github.com/phuslu/log"
)

func SetUpLogger() {
	// Always use console writer for containers to ensure logs go to stdout
	log.DefaultLogger = log.Logger{
		Level:      log.DebugLevel,
		TimeFormat: "15:04:05.123Z",
		Caller:     1,
		Writer: &log.ConsoleWriter{
			ColorOutput:    log.IsTerminal(os.Stderr.Fd()),
			QuoteString:    true,
			EndWithMessage: true,
		},
	}
}
