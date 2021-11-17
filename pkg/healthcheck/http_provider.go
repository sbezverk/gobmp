package healthcheck

import (
	"fmt"
	nhttp "net/http"
	"os"
	"strconv"

	"github.com/sbezverk/gobmp/pkg/http"
)

const (
	theHTTPMethod = "Get"
	theHTTPPath   = "/health"
)

// Checker is the function that implements the health check
//
// Returns an error when the check fails
// Returns no error when the check is successful
type Checker func() error

// EnableHTTPProvider is used for enabling healthcheck HTTP endpoint
func EnableHTTPProvider(checker Checker, done <-chan struct{}) <-chan error {
	var errors = make(chan error, 1)

	serverPort, err := strconv.Atoi(getHealthCheckHTTPPort())
	if err != nil {
		errors <- fmt.Errorf("failed to specify a healthcheck port, %v", err)
	}

	go func() {
		server, err := http.NewServer(serverPort, &[]http.Route{
			{
				Path:    theHTTPPath,
				Method:  theHTTPMethod,
				Handler: &healthCheckHTTPHandler{checker: checker},
			},
		})
		if err != nil {
			errors <- err
			return
		}
		errors <- server.Run(done)
	}()

	return errors
}

type healthCheckHTTPHandler struct {
	checker Checker
}

func (hchh *healthCheckHTTPHandler) ServeHTTP(w nhttp.ResponseWriter, r *nhttp.Request) {
	err := hchh.checker()
	if err != nil {
		w.WriteHeader(nhttp.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("Failed due to %v", err)))
		return
	}

	w.WriteHeader(nhttp.StatusOK)
}

func getHealthCheckHTTPPort() string {
	port, found := os.LookupEnv("HEALTHCHECK_HTTP_PORT")
	if found {
		return port
	}
	return "3000"
}
