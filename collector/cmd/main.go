package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector"
	"github.com/tensorchord/watchu/collector/execve"
	"github.com/tensorchord/watchu/collector/internal/logger"
	"github.com/tensorchord/watchu/collector/internal/tool"
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
	address := flag.String("gateway", "", "the gateway address, e.g., 'http://localhost:8080' (optional). Leave it empty to disable pushing events to the gateway")
	tetragonPath := flag.String("tetragon-path", "",
		fmt.Sprintf("the Tetragon gRPC path (Unix domain socket or HTTP) (optional). e.g., '%s'. Leave it empty to disable Tetragon integration", TetragonSocket))
	flag.Parse()

	logger.SetUpLogger(*debug)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	gatewayClient, err := collector.NewGatewayClient(ctx, *address)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize gateway client")
	}

	err = tool.InitEBPF()
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize eBPF")
	}

	sslProbe := sslsniff.NewSSLProbe(SSLPath, rustlsPath, gatewayClient)
	go sslProbe.Start(ctx)

	stdioProbe := stdio.NewStdioProbe(gatewayClient)
	go stdioProbe.Start(ctx)

	pgProbe := postgres.NewPostgresProbe(gatewayClient)
	go pgProbe.Start(ctx)

	if len(*tetragonPath) > 0 {
		log.Info().Str("socket", *tetragonPath).Msg("enable Tetragon integration")
		tetragonClient, err := execve.NewTetragonClient(*tetragonPath, gatewayClient, ctx)
		if err != nil {
			log.Panic().Err(err).Msg("failed to create Tetragon client")
		}
		defer tetragonClient.Close()
		go tetragonClient.Start(ctx)
	}

	<-ctx.Done()
	sslProbe.Close()
	stdioProbe.Close()
	pgProbe.Close()
}
