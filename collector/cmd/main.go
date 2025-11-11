package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu/collector"
	"github.com/tensorchord/watchu/collector/sslsniff"
	"github.com/tensorchord/watchu/collector/stdio"
)

const (
	TETRAGON_SOCKET = "unix:///var/run/tetragon/tetragon.sock"
)

func main() {
	collector.SetUpLogger()
	SSLPath := flag.String("ssl-path", "", "extra user binary path to attach SSL uprobes (optional)")
	address := flag.String("gateway", "", "the gateway address, e.g., 'http://localhost:8080'. Leave it empty to disable pushing events to the gateway")
	tetragonSocket := flag.String("tetragon-socket", "",
		fmt.Sprintf("the Tetragon gRPC socket path, e.g., '%s'. Leave it empty will disable Tetragon integration", TETRAGON_SOCKET))
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	gatewayClient, err := collector.NewGatewayClient(ctx, *address)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize gateway client")
	}

	err = collector.InitEBPF()
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize eBPF")
	}

	sslProbe := sslsniff.NewSSLProbe(SSLPath, gatewayClient)
	go sslProbe.Start(ctx)

	stdioProbe := stdio.NewStdioProbe()
	go stdioProbe.Start()

	if len(*tetragonSocket) > 0 {
		log.Info().Str("socket", *tetragonSocket).Msg("enable Tetragon integration")
		tetragonClient, err := collector.NewTetragonClient(*tetragonSocket, gatewayClient)
		if err != nil {
			log.Panic().Err(err).Msg("failed to create Tetragon client")
		}
		defer tetragonClient.Close()
		go tetragonClient.Run(ctx)
	}

	<-ctx.Done()
	sslProbe.Close()
	stdioProbe.Close()
}
