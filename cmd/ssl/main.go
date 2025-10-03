package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	"github.com/tensorchord/watchu"
	"github.com/tensorchord/watchu/sslsniff"
)

func main() {
	watchu.SetUpLogger()
	binaryPath := flag.String("binary-path", "", "extra user binary path to attach SSL uprobes (optional)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sslProbe := sslsniff.NewSSLProbe(binaryPath)

	go func() {
		<-ctx.Done()
		sslProbe.Close()
	}()

	sslProbe.Start(ctx)
}
