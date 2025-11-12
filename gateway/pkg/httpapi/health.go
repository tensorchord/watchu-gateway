package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

func registerHealth(engine *gin.Engine, pool *pgxpool.Pool) {
	engine.GET("/healthz", health)
	// ready depends on external deps; check DB if available.
	engine.GET("/readyz", func(c *gin.Context) {
		if pool != nil {
			if err := pool.Ping(c.Request.Context()); err != nil {
				c.JSON(http.StatusServiceUnavailable, ErrorResponse{Error: "database not ready"})
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
