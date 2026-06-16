package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
)

var (
	testFile string
	apiSrv   string
	kafkaSrv string
)

func init() {
	flag.StringVar(&testFile, "test-file", "", "Path to the test file")
	flag.StringVar(&apiSrv, "api-srv", "", "API server address")
	flag.StringVar(&kafkaSrv, "kafka-srv", "", "Kafka server address")
}

func validateAndNormalize(f *Fixture) error {
	if f.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema version: %d", f.SchemaVersion)
	}
	f.Name = strings.TrimSpace(f.Name)
	if f.Name == "" {
		return fmt.Errorf("name is required")
	}
	f.Inject.Path = strings.TrimSpace(f.Inject.Path)
	if f.Inject.Path == "" {
		f.Inject.Path = injectPath
	}
	f.Observe.Source = strings.TrimSpace(f.Observe.Source)
	if f.Observe.Source == "" {
		return fmt.Errorf("observe.source is required")
	}
	f.Observe.Topic = strings.TrimSpace(f.Observe.Topic)
	if f.Observe.Topic == "" {
		return fmt.Errorf("observe.topic is required")
	}
	f.Observe.timeoutSec = 120
	if f.Observe.Timeout != "" {
		t, err := strconv.ParseInt(f.Observe.Timeout, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid observe.timeout: %v", err)
		}
		if t <= 0 {
			return fmt.Errorf("observe.timeout must be positive")
		}
		f.Observe.timeoutSec = int(t)
	}
	var body any
	if err := json.Unmarshal(f.Inject.Body, &body); err != nil {
		return fmt.Errorf("invalid inject.body: %v", err)
	}
	if len(f.Observe.Match) == 0 {
		return fmt.Errorf("observe.match is required")
	}
	switch {
	case len(f.Expect.Equals) > 0:
	case len(f.Expect.Contains) > 0:
	case len(f.Expect.Present) > 0:
	case len(f.Expect.Absent) > 0:
	default:
		return fmt.Errorf("expect is required for a successful test")
	}
	if f.Cleanup != nil {
		f.Cleanup.Path = strings.TrimSpace(f.Cleanup.Path)
		if f.Cleanup.Path == "" {
			f.Cleanup.Path = injectPath
		}
		var body any
		if err := json.Unmarshal(f.Cleanup.Body, &body); err != nil {
			return fmt.Errorf("invalid cleanup.body: %v", err)
		}
	}

	return nil
}

func injectBody(apiSrv, path string, body json.RawMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apiPath, err := url.JoinPath(apiSrv, path)
	if err != nil {
		return fmt.Errorf("failed to join API path: %v", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		apiPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST failed: status=%s body=%s", resp.Status, string(respBody))
	}

	var out InjectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	if out.Accepted == len(out.Updates) {
		for _, update := range out.Updates {
			if err != nil {
				break
			}
			if !update.Queued {
				err = fmt.Errorf("injected update not queued: prefix=%s action=%s bytes=%d", update.Prefix, update.Action, update.Bytes)
				glog.Infof("Injected update: prefix=%s action=%s bytes=%d", update.Prefix, update.Action, update.Bytes)
			} else {
				if glog.V(3) {
					glog.Infof("Injected update queued: prefix=%s action=%s", update.Prefix, update.Action)
				}
			}
		}
	} else {
		return fmt.Errorf("inject not accepted: %v", out)
	}

	return err
}

func checkSession(apiSrv, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apiPath, err := url.JoinPath(apiSrv, path)
	if err != nil {
		return fmt.Errorf("failed to join API path: %v", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		apiPath,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET failed: status=%s body=%s", resp.Status, string(respBody))
	}

	var out SessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("failed to decode response: %v", err)
	}

	return nil
}

func main() {
	_ = flag.Set("logtostderr", "true")
	flag.Parse()

	testFile = strings.TrimSpace(testFile)
	if testFile == "" {
		glog.Errorf("test file name is required")
		os.Exit(1)
	}
	apiSrv = strings.TrimSpace(apiSrv)
	if apiSrv == "" {
		glog.Errorf("API server address is required")
		os.Exit(1)
	}
	_, err := url.Parse(apiSrv)
	if err != nil {
		glog.Errorf("invalid API server address: %v", err)
		os.Exit(1)
	}
	kafkaSrv = strings.TrimSpace(kafkaSrv)
	if kafkaSrv == "" {
		glog.Errorf("Kafka server address is required")
		os.Exit(1)
	}
	f, err := os.Open(testFile)
	if err != nil {
		glog.Errorf("failed to open test file: %v", err)
		os.Exit(1)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		glog.Errorf("failed to read test file: %v", err)
		os.Exit(1)
	}
	var fixture Fixture
	if err := json.Unmarshal(b, &fixture); err != nil {
		glog.Errorf("failed to unmarshal test file: %v", err)
		os.Exit(1)
	}
	if err := validateAndNormalize(&fixture); err != nil {
		glog.Errorf("validation failed: %v", err)
		os.Exit(1)
	}

	if err := checkSession(apiSrv, "/readyz"); err != nil {
		glog.Errorf("session check failed: %v", err)
		os.Exit(1)
	}

	if err := injectBody(apiSrv, fixture.Inject.Path, fixture.Inject.Body); err != nil {
		glog.Errorf("inject failed: %v", err)
		os.Exit(1)
	}

	if fixture.Cleanup != nil {
		// For now just sleep for 60 seconds before clean up to check the router
		time.Sleep(time.Second * 60)

		if err := injectBody(apiSrv, fixture.Cleanup.Path, fixture.Cleanup.Body); err != nil {
			glog.Errorf("cleanup failed: %v", err)
			os.Exit(1)
		}
	}
	glog.Infof("Test '%s' executed successfully", fixture.Name)
}
