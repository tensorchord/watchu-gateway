package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/phuslu/log"

	"github.com/tensorchord/watchu"
	"github.com/tensorchord/watchu/sslsniff"
	"github.com/tensorchord/watchu/stdio"
)

const (
	TETRAGON_SOCKET = "unix:///var/run/tetragon/tetragon.sock"
)

func main() {
	watchu.SetUpLogger()
	binaryPath := flag.String("binary-path", "", "extra user binary path to attach SSL uprobes (optional)")
	dsn := flag.String("db", "watchu.db", "a duckdb database source name")
	tetragonSocket := flag.String("tetragon-socket", "",
		fmt.Sprintf("the Tetragon gRPC socket path, e.g., '%s'. Leave it empty to disable Tetragon integration", TETRAGON_SOCKET))
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	storage, err := watchu.NewStorage(*dsn)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize storage")
	}

	err = watchu.InitEBPF()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize eBPF")
	}

	sslProbe := sslsniff.NewSSLProbe(binaryPath, storage)
	go sslProbe.Start(ctx)

	stdioProbe := stdio.NewStdioProbe()
	go stdioProbe.Start()

	if len(*tetragonSocket) > 0 {
		log.Info().Str("socket", *tetragonSocket).Msg("enable Tetragon integration")
		tetragonClient, err := watchu.NewTetragonClient(*tetragonSocket, storage)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create Tetragon client")
		}
		defer tetragonClient.Close()
		go tetragonClient.Run(ctx)
	}

	<-ctx.Done()
	sslProbe.Close()
	stdioProbe.Close()
	storage.Close()
}
