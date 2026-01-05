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
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
	"github.com/tensorchord/watchu/gateway/pkg/server"
	"github.com/tensorchord/watchu/gateway/pkg/skillsecurity"
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

	securityInsightSvc, err := securityinsight.NewService(queries, securityinsight.Options{
		PromptInjectionEnabled:           cfg.PromptInjectionEnabled,
		PromptInjectionAPIBase:           cfg.PromptInjectionAPIBase,
		PromptInjectionAPIKey:            cfg.PromptInjectionAPIKey,
		PromptInjectionModel:             cfg.PromptInjectionModel,
		PromptInjectionMode:              cfg.PromptInjectionMode,
		PromptInjectionTimeout:           cfg.PromptInjectionTimeout,
		PromptInjectionMaxTokens:         cfg.PromptInjectionMaxTokens,
		PromptInjectionBatchSize:         cfg.PromptInjectionBatchSize,
		PromptInjectionMaxRetries:        cfg.PromptInjectionMaxRetries,
		PromptInjectionSampleRate:        cfg.PromptInjectionSampleRate,
		PromptInjectionMaxQPS:            cfg.PromptInjectionMaxQPS,
		PromptInjectionMaxPromptLen:      cfg.PromptInjectionMaxPromptLen,
		PromptInjectionStripTools:        cfg.PromptInjectionStripTools,
		PromptInjectionExtractUser:       cfg.PromptInjectionExtractUser,
		PromptInjectionEvidenceVerbosity: cfg.PromptInjectionEvidenceVerbosity,
		PromptInjectionEvidenceMaxChars:  cfg.PromptInjectionEvidenceMaxChars,
		ThreatInsightEnabled:             cfg.ThreatInsightEnabled,
		ThreatInsightBaseURL:             cfg.ThreatInsightBaseURL,
		ThreatInsightAPIKey:              cfg.ThreatInsightAPIKey,
		ThreatInsightModel:               cfg.ThreatInsightModel,
		ThreatInsightTimeout:             cfg.ThreatInsightTimeout,
	}, slog.Default())

	if err != nil {
		slog.Error("security insight service initialization failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	var skillSecuritySvc *skillsecurity.Service
	if cfg.SkillRunnerBaseURL != "" {
		runnerClient := skillsecurity.NewRunnerClient(cfg.SkillRunnerBaseURL, cfg.SkillRunnerTimeout)
		skillSecuritySvc = skillsecurity.NewService(queries, runnerClient, securityInsightSvc, slog.Default())
	}

	router := httpapi.NewRouter(httpapi.Dependencies{
		Ingest:          ingestService,
		Queries:         queries,
		Pool:            pool,
		SecurityInsight: securityInsightSvc,
		SkillSecurity:   skillSecuritySvc,
		SkillUploadDir:  cfg.SkillUploadDir,
	})
	srv := server.New(cfg.Address, router)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.AnalysisEnabled {
		scheduler := analysis.NewScheduler(
			pool,
			cfg.AnalysisTickInterval,
			cfg.AnalysisLookback,
			cfg.AnalysisHorizon,
			cfg.AnalysisLag,
			cfg.AnalysisMaxWindow,
			securityInsightSvc.PromptInjectionService(),
			slog.Default(),
		)
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
