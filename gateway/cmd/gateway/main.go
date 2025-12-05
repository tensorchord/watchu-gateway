package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/tensorchord/watchu/gateway/pkg/analysis"
	"github.com/tensorchord/watchu/gateway/pkg/config"
	"github.com/tensorchord/watchu/gateway/pkg/database"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/httpapi"
	"github.com/tensorchord/watchu/gateway/pkg/ingest"
	"github.com/tensorchord/watchu/gateway/pkg/promptinjection"
	"github.com/tensorchord/watchu/gateway/pkg/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	pool, err := database.NewPool(context.Background(), cfg.DatabaseURL)
	if err != nil {
		slog.Error("database connect failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()

	ingestService := ingest.NewService(pool)
	queries := sqlc.New(pool)
	promptSvc := promptinjection.NewService(queries, promptinjection.Options{
		Enabled:         cfg.PromptInjectionEnabled,
		APIBase:         cfg.PromptInjectionAPIBase,
		APIKey:          cfg.PromptInjectionAPIKey,
		Model:           cfg.PromptInjectionModel,
		Mode:            cfg.PromptInjectionMode,
		Timeout:         cfg.PromptInjectionTimeout,
		BatchSize:       cfg.PromptInjectionBatchSize,
		MaxRetries:      cfg.PromptInjectionMaxRetries,
		SampleRate:      cfg.PromptInjectionSampleRate,
		MaxQPS:          cfg.PromptInjectionMaxQPS,
		MaxPromptLength: cfg.PromptInjectionMaxPromptLen,
		StripToolCalls:  cfg.PromptInjectionStripTools,
	}, slog.Default())

	router := httpapi.NewRouter(httpapi.Dependencies{
		Ingest:  ingestService,
		Queries: queries,
		Pool:    pool,
		Prompt:  promptSvc,
	})
	srv := server.New(cfg.Address, router)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.AnalysisEnabled {
		scheduler := analysis.NewScheduler(pool, cfg.AnalysisTickInterval, cfg.AnalysisLookback, cfg.AnalysisHorizon, cfg.AnalysisLag, promptSvc, slog.Default())
		go scheduler.Run(ctx)
	}

	go func() {
		if err := srv.Start(); err != nil {
			if err != context.Canceled && err != http.ErrServerClosed {
				slog.Error("server stopped with error", slog.String("error", err.Error()))
			}
		}
	}()

	<-ctx.Done()
	stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
