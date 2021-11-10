package http

import (
	"context"
	"fmt"
	nhttp "net/http"
	"time"

	mux "github.com/gorilla/mux"
)

// Route is an HTTP route
type Route struct {
	Path    string
	Method  string
	Handler nhttp.Handler
}

// Server is the app server implementation
type Server struct {
	srv    *nhttp.Server
	router *mux.Router
	routes *[]Route
}

// NewServer creates a new server
func NewServer(port int, routes *[]Route) (*Server, error) {
	r := mux.NewRouter()
	s := Server{
		srv: &nhttp.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: r,
		},
		router: r,
		routes: routes,
	}
	return &s, nil
}

func registerMuxRoutes(r *mux.Router, routes *[]Route) {
	for _, route := range *routes {
		r.Handle(route.Path, route.Handler).Methods(route.Method)
	}
}

// Run implements the custom server run logic
func (s *Server) Run(done <-chan struct{}) error {
	registerMuxRoutes(s.router, s.routes)

	var errors = make(chan error, 1)
	go func() {
		if err := s.srv.ListenAndServe(); err != nil {
			errors <- err
		}
	}()

	fmt.Printf("Server started\n")

	select {
	case err := <-errors:
		return err
	case <-done:
		fmt.Printf("Server stopped\n")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer func() {
			cancel()
		}()

		if err := s.srv.Shutdown(ctx); err != nil {
			return err
		}
		fmt.Printf("Server exited properly")
		return nil
	}
}
