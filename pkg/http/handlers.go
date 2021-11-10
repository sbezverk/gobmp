package http

import (
	nhttp "net/http"
)

// HealthHandler is the health handler type for gobmp
type HealthHandler struct{}

// ServeHTTP is the HealthHandler interface implementation
func (hh *HealthHandler) ServeHTTP(w nhttp.ResponseWriter, r *nhttp.Request) {}

// LoadDefaultRoutes loads the default routes to be used by the HTTP server
func LoadDefaultRoutes() *[]Route {
	routes := make([]Route, 1)
	routes[0] = Route{
		Path:    "/health",
		Method:  "GET",
		Handler: &HealthHandler{},
	}

	return &routes
}
