package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

const promptReadyTimeout = 5 * time.Second

func registerHealth(engine *gin.Engine, pool *pgxpool.Pool, prompt PromptReadiness) {
	engine.GET("/healthz", health)
	// ready depends on external deps; check DB if available.
	engine.GET("/readyz", func(c *gin.Context) {
		if pool != nil {
			if err := pool.Ping(c.Request.Context()); err != nil {
				respondError(c, http.StatusServiceUnavailable, "database_not_ready", "database not ready", nil)
				return
			}
		}
		if prompt != nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), promptReadyTimeout)
			defer cancel()
			if err := prompt.Ready(ctx); err != nil {
				respondError(c, http.StatusServiceUnavailable, "prompt_detection_not_ready", "prompt detection not ready", nil)
				return
			}
		}
		ready(c)
	})
}

// health godoc
// @Summary Health check
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /healthz [get]
func health(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{Status: "ok"})
}

// ready godoc
// @Summary Readiness check
// @Tags health
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /readyz [get]
func ready(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{Status: "ready"})
}
