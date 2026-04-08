package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/execve"
	"github.com/tensorchord/watchu/collector/export"
	"github.com/tensorchord/watchu/collector/fileop"
	"github.com/tensorchord/watchu/collector/internal/logger"
	"github.com/tensorchord/watchu/collector/internal/tool"
	"github.com/tensorchord/watchu/collector/otelrecv"
	"github.com/tensorchord/watchu/collector/postgres"
	"github.com/tensorchord/watchu/collector/sslsniff"
	"github.com/tensorchord/watchu/collector/stdio"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug-level colorful log")
	SSLPath := flag.String("ssl-path", "", "extra user binary path to attach SSL uprobes (optional)")
	// TODO: rustls gets the encrypted data, we need to decrypt with the session key
	rustlsPath := flag.String("rustls-path", "", "extra user binary path to attach rustls uprobes (optional)")
	exportTarget := flag.String("export", "", "event export target: empty=discard, http[s]://...=gateway, file://...=local jsonl")
	otelAddr := flag.String("otel-addr", "", "OTLP gRPC receiver address, e.g., ':4317' (optional). Enable to capture AI tool telemetry")
	flag.Parse()

	logger.SetUpLogger(*debug)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	exporter, err := export.NewExporter(ctx, *exportTarget)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize exporter")
	}
	defer func() {
		if err := exporter.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close exporter")
		}
	}()

	err = tool.InitEBPF()
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize eBPF")
	}

	execProbe, err := execve.NewProcExecProbe()
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize exec probe")
	}
	defer execProbe.Close()
	go execProbe.Start(ctx)
	go execProbe.IngestExecEvents(ctx, exporter)

	sslProbe := sslsniff.NewSSLProbe(execProbe, SSLPath, rustlsPath, exporter)
	defer sslProbe.Close()
	go sslProbe.Start(ctx)

	stdioProbe, err := stdio.NewStdioProbe(exporter)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize stdio probe")
	}
	defer stdioProbe.Close()
	go stdioProbe.Start(ctx)

	pgProbe := postgres.NewPostgresProbe(exporter)
	defer pgProbe.Close()
	go pgProbe.Start(ctx)

	fileOpProbe, err := fileop.NewFileOpProbe(exporter)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize fileop probe")
	}
	defer fileOpProbe.Close()
	go fileOpProbe.Start(ctx)

	// OTEL receiver for AI tool telemetry (alternative to SSL interception)
	var otelReceiver *otelrecv.OTELReceiver
	if len(*otelAddr) > 0 {
		log.Info().Str("addr", *otelAddr).Msg("enable OTEL receiver for AI tool telemetry")
		otelReceiver, err = otelrecv.NewOTELReceiver(ctx, *otelAddr, exporter)
		if err != nil {
			log.Panic().Err(err).Msg("failed to create OTEL receiver")
		}
		defer otelReceiver.Close()
		go otelReceiver.Start(ctx)
	}

	<-ctx.Done()
}
