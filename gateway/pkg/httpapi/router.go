package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	docs "github.com/tensorchord/watchu/gateway/pkg/docs"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tensorchord/watchu/gateway/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/gateway/pkg/ingest"
	"github.com/tensorchord/watchu/gateway/pkg/securityinsight"
)

// Dependencies captures services the HTTP layer relies on.
type Dependencies struct {
	Ingest          *ingest.Service
	Queries         *sqlc.Queries
	Pool            *pgxpool.Pool
	SecurityInsight *securityinsight.Service
}

// PromptReadiness exposes readiness for prompt injection integrations.
type PromptReadiness interface {
	Ready(ctx context.Context) error
}

// NewRouter returns a Gin engine with registered routes based on dependencies.
func NewRouter(deps Dependencies) *gin.Engine {
	engine := gin.New()
	engine.Use(gin.Recovery())

	corsConfig := cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
	engine.Use(cors.New(corsConfig))

	docs.SwaggerInfo.BasePath = "/"
	registerHealth(engine, deps.Pool, deps.SecurityInsight)
	engine.GET("/metrics", gin.WrapH(promhttp.Handler()))
	swaggerHandler := ginSwagger.WrapHandler(swaggerFiles.Handler)
	engine.GET("/swagger/*any", func(c *gin.Context) {
		any := c.Param("any")
		if any == "" || any == "/" {
			redirectSwaggerIndex(c)
			return
		}
		swaggerHandler(c)
	})
	engine.GET("/swagger", redirectSwaggerIndex)
	engine.GET("/", redirectSwaggerIndex)

	api := engine.Group("/api/v1")

	if deps.Ingest != nil {
		registerIngestRoutes(api.Group("/ingest"), deps.Ingest)
	}

	if deps.Queries != nil {
		analysisGroup := api.Group("/analysis")
		registerAnalyticsRoutes(analysisGroup, deps.Queries)
	}

	if deps.SecurityInsight != nil {
		registerSecurityInsightRoutes(api, deps.SecurityInsight)
	}

	return engine
}

func redirectSwaggerIndex(c *gin.Context) {
	c.Redirect(http.StatusTemporaryRedirect, "/swagger/index.html")
}
