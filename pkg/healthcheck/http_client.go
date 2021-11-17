package healthcheck

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

// HTTPHealthCheck triggers HTTP health check client
func HTTPHealthCheck() error {
	var (
		client = http.Client{
			Timeout: time.Second,
		}

		url, _ = url.Parse(fmt.Sprintf("%s://%s:%s/%s", getHealthCheckHTTPScheme(), getHealthCheckHTTPHost(), getHealthCheckHTTPPort(), theHTTPPath))
	)
	resp, err := client.Do(&http.Request{
		Method: theHTTPMethod,
		URL:    url,
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		message, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed with status: %d, message: %s", resp.StatusCode, string(message))
	}

	return nil
}

func getHealthCheckHTTPHost() string {
	host, found := os.LookupEnv("HEALTHCHECK_HTTP_HOST")
	if found {
		return host
	}
	return "localhost"
}

func getHealthCheckHTTPScheme() string {
	scheme, found := os.LookupEnv("HEALTHCHECK_HTTP_SCHEME")
	if found {
		return scheme
	}
	return "http"
}
