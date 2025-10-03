package watchu

import (
	"os"

	"github.com/phuslu/log"
)

func SetUpLogger() {
	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			TimeFormat: "15:04:05.123Z",
			Caller:     1,
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				QuoteString:    true,
				EndWithMessage: true,
			},
		}
	} else {
		log.DefaultLogger = log.Logger{
			Level: log.DebugLevel,
			Writer: &log.AsyncWriter{
				ChannelSize:   4096,
				DiscardOnFull: false,
				Writer: &log.FileWriter{
					Filename:   "watchu.log",
					FileMode:   0600,
					MaxSize:    50 * 1024 * 1024,
					MaxBackups: 7,
					LocalTime:  false,
				},
			},
		}
	}
}
