package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	docs "github.com/tensorchord/watchu/pkg/docs"

	"github.com/tensorchord/watchu/pkg/gen/sqlc"
	"github.com/tensorchord/watchu/pkg/ingest"
)

// Dependencies captures services the HTTP layer relies on.
type Dependencies struct {
	Ingest  *ingest.Service
	Queries *sqlc.Queries
}

// NewRouter returns a Gin engine with registered routes based on dependencies.
func NewRouter(deps Dependencies) *gin.Engine {
	engine := gin.New()
	engine.Use(gin.Recovery())

	docs.SwaggerInfo.BasePath = "/"
	registerHealth(engine)
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
		registerAnalyticsRoutes(api.Group("/analysis"), deps.Queries)
	}

	return engine
}

func redirectSwaggerIndex(c *gin.Context) {
	c.Redirect(http.StatusTemporaryRedirect, "/swagger/index.html")
}
