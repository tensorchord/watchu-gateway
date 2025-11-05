package server

import (
	"context"
	"net/http"
)

// Server wraps an http.Server to support graceful shutdown.
type Server struct {
	httpServer *http.Server
}

// New builds a Server instance with the supplied handler and address.
func New(addr string, handler http.Handler) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:    addr,
			Handler: handler,
		},
	}
}

// Start begins listening for incoming HTTP traffic.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown attempts a graceful server stop.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
