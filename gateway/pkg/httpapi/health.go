package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func registerHealth(engine *gin.Engine) {
	engine.GET("/healthz", health)
	engine.GET("/readyz", ready)
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
