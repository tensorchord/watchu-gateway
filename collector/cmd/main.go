package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector/execve"
	"github.com/tensorchord/watchu/collector/export"
	"github.com/tensorchord/watchu/collector/internal/logger"
	"github.com/tensorchord/watchu/collector/internal/tool"
	"github.com/tensorchord/watchu/collector/otelrecv"
	"github.com/tensorchord/watchu/collector/postgres"
	"github.com/tensorchord/watchu/collector/sslsniff"
	"github.com/tensorchord/watchu/collector/stdio"
)

const (
	TetragonSocket = "unix:///var/run/tetragon/tetragon.sock"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug-level colorful log")
	SSLPath := flag.String("ssl-path", "", "extra user binary path to attach SSL uprobes (optional)")
	// TODO: rustls gets the encrypted data, we need to decrypt with the session key
	rustlsPath := flag.String("rustls-path", "", "extra user binary path to attach rustls uprobes (optional)")
	exportTarget := flag.String("export", "", "event export target: empty=discard, http[s]://...=gateway, file://...=local jsonl")
	tetragonPath := flag.String("tetragon-path", "",
		fmt.Sprintf("the Tetragon gRPC path (Unix domain socket or HTTP) (optional). e.g., '%s'. Leave it empty to disable Tetragon integration", TetragonSocket))
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

	sslProbe := sslsniff.NewSSLProbe(SSLPath, rustlsPath, exporter)
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

	if len(*tetragonPath) > 0 {
		log.Info().Str("socket", *tetragonPath).Msg("enable Tetragon integration")
		tetragonClient, err := execve.NewTetragonClient(*tetragonPath, exporter, ctx)
		if err != nil {
			log.Panic().Err(err).Msg("failed to create Tetragon client")
		}
		defer tetragonClient.Close()
		go tetragonClient.Start(ctx)
	}

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
