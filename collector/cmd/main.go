package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/tensorchord/watchu/collector/tcpconn"
	"github.com/tensorchord/watchu/collector/tui"
)

const fileOpPolicyExample = `{
	"read":{
		"prefixes":["/etc/"],
		"home_prefixes":[".ssh/"],
		"suffixes":[".pem"]
	},
	"write":{
		"prefixes":["/var/log/"],
		"home_prefixes":[".config/"],
		"suffixes":[".env"]
	}
}`

type collectorConfig struct {
	exportTarget     string
	sslPath          string
	rustlsPath       string
	otelAddr         string
	fileOpPolicyPath string
}

func main() {
	debug := flag.Bool("debug", false, "enable debug-level colorful log")
	SSLPath := flag.String("ssl-path", "", "extra user binary path to attach SSL uprobes (optional)")
	// TODO: rustls gets the encrypted data, we need to decrypt with the session key
	rustlsPath := flag.String("rustls-path", "", "extra user binary path to attach rustls uprobes (optional)")
	exportTarget := flag.String("export", "", "event export target: empty=discard, http[s]://...=gateway, file://...=local jsonl")
	logPath := flag.String("log-path", "", "local collector log file path; empty=stderr")
	otelAddr := flag.String("otel-addr", "", "OTLP gRPC receiver address, e.g., ':4317' (optional). Enable to capture AI tool telemetry")
	fileOpPolicyPath := flag.String("fileop-policy", "", fmt.Sprintf(`path to fileop match policy config (.json only); empty=built-in. Example: %s`, fileOpPolicyExample))
	enableTUI := flag.Bool("tui", false, "render a terminal dashboard backed by a local JSONL export file; defaults logs to a local file besides to the export file")
	flag.Parse()

	resolvedExportTarget, tuiPath, resolvedLogPath, tempDir, err := resolveRuntimePaths(*exportTarget, *logPath, *enableTUI)
	if err != nil {
		log.Panic().Err(err).Msg("failed to resolve export target")
	}
	if tempDir != "" {
		defer func() {
			if err := os.RemoveAll(tempDir); err != nil {
				log.Error().Err(err).Str("path", tempDir).Msg("failed to remove tui temp dir")
			}
		}()
	}

	logFile, err := logger.SetUpLogger(*debug, resolvedLogPath)
	if err != nil {
		log.Panic().Err(err).Msg("failed to initialize logger")
	}
	if logFile != nil {
		defer func() {
			if err := logFile.Close(); err != nil {
				log.Error().Err(err).Msg("failed to close log file")
			}
		}()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := collectorConfig{
		exportTarget:     resolvedExportTarget,
		sslPath:          *SSLPath,
		rustlsPath:       *rustlsPath,
		otelAddr:         *otelAddr,
		fileOpPolicyPath: *fileOpPolicyPath,
	}

	if *enableTUI {
		collectorErrCh := make(chan error, 1)
		go func() {
			err := runCollector(ctx, cfg)
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Error().Err(err).Msg("collector stopped")
				cancel()
			}
			collectorErrCh <- err
		}()

		if err := tui.Run(ctx, tuiPath); err != nil {
			log.Panic().Err(err).Msg("failed to run tui")
		}
		cancel()
		if err := <-collectorErrCh; err != nil && !errors.Is(err, context.Canceled) {
			log.Panic().Err(err).Msg("collector exited with error")
		}
		return
	}

	if err := runCollector(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Panic().Err(err).Msg("collector exited with error")
	}
}

func runCollector(ctx context.Context, cfg collectorConfig) error {
	exporter, err := export.NewExporter(ctx, cfg.exportTarget)
	if err != nil {
		return fmt.Errorf("initialize exporter: %w", err)
	}
	defer func() {
		if err := exporter.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close exporter")
		}
	}()

	if err := tool.InitEBPF(); err != nil {
		return fmt.Errorf("initialize eBPF: %w", err)
	}

	execProbe, err := execve.NewProcExecProbe()
	if err != nil {
		return fmt.Errorf("initialize exec probe: %w", err)
	}
	defer execProbe.Close()
	go execProbe.Start(ctx)
	go execProbe.IngestExecEvents(ctx, exporter)

	sslProbe := sslsniff.NewSSLProbe(execProbe, &cfg.sslPath, &cfg.rustlsPath, exporter)
	defer sslProbe.Close()
	go sslProbe.Start(ctx)

	stdioProbe, err := stdio.NewStdioProbe(exporter)
	if err != nil {
		return fmt.Errorf("initialize stdio probe: %w", err)
	}
	defer stdioProbe.Close()
	go stdioProbe.Start(ctx)

	pgProbe := postgres.NewPostgresProbe(exporter)
	defer pgProbe.Close()
	go pgProbe.Start(ctx)

	tcpConnProbe, err := tcpconn.NewTCPConnProbe(exporter)
	if err != nil {
		return fmt.Errorf("initialize tcpconn probe: %w", err)
	}
	defer tcpConnProbe.Close()
	go tcpConnProbe.Start(ctx)

	fileOpPolicy, err := fileop.LoadPolicy(cfg.fileOpPolicyPath)
	if err != nil {
		return fmt.Errorf("load fileop policy %q: %w", cfg.fileOpPolicyPath, err)
	}

	fileOpProbe, err := fileop.NewFileOpProbe(exporter, fileOpPolicy)
	if err != nil {
		return fmt.Errorf("initialize fileop probe: %w", err)
	}
	defer fileOpProbe.Close()
	go fileOpProbe.Start(ctx)

	var otelReceiver *otelrecv.OTELReceiver
	if len(cfg.otelAddr) > 0 {
		log.Info().Str("addr", cfg.otelAddr).Msg("enable OTEL receiver for AI tool telemetry")
		otelReceiver, err = otelrecv.NewOTELReceiver(ctx, cfg.otelAddr, exporter)
		if err != nil {
			return fmt.Errorf("create OTEL receiver: %w", err)
		}
		defer otelReceiver.Close()
		go otelReceiver.Start(ctx)
	}

	<-ctx.Done()
	return context.Cause(ctx)
}

func resolveRuntimePaths(target string, logPath string, enableTUI bool) (string, string, string, string, error) {
	if !enableTUI {
		return target, "", logPath, "", nil
	}

	if target == "" {
		path, err := os.MkdirTemp("", "watchu-tui-")
		if err != nil {
			return "", "", "", "", fmt.Errorf("create tui temp dir: %w", err)
		}
		filePath := filepath.Join(path, "events.jsonl")
		if logPath == "" {
			logPath = filepath.Join(path, "watchu.log")
		}
		return "file://" + filePath, filePath, logPath, path, nil
	}

	filePath, err := export.FilePathFromTarget(target)
	if err != nil {
		return "", "", "", "", fmt.Errorf("tui mode requires --export to be a file:// target: %w", err)
	}
	if logPath == "" {
		logPath = filepath.Join(filepath.Dir(filePath), "watchu.log")
	}
	return target, filePath, logPath, "", nil
}
