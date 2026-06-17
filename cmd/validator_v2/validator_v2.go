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
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/tools/kafka_consumer"
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
	dec := json.NewDecoder(bytes.NewReader(f.Inject.Body))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
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
		dec := json.NewDecoder(bytes.NewReader(f.Cleanup.Body))
		dec.UseNumber()
		if err := dec.Decode(&body); err != nil {
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
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	if err := dec.Decode(&fixture); err != nil {
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(fixture.Observe.timeoutSec)*time.Second)
	defer cancel()
	kafkaCfg := kafka_consumer.KafkaConsumerConfig{
		Brokers:        []string{kafkaSrv},
		ConsumerGroups: []string{"gobmp_validator"},
		Topics:         []string{fixture.Observe.Topic},
	}
	consumer, err := kafka_consumer.NewKafkaConsumer(ctx, "gobmp_validator", "gobmp_validator_group_"+strconv.FormatInt(time.Now().UnixNano(), 10), &kafkaCfg)
	if err != nil {
		glog.Errorf("failed to create Kafka consumer: %v", err)
		os.Exit(1)
	}
	consumer.Start()
	defer consumer.Stop()

	msgCh := make(chan observedKafkaMessage, 100)
	errCh := make(chan error, 1)
	topicsDescr := consumer.GetTopics()
	// There is a single topic, so use index 0 to get the batch channel
	batchCh := topicsDescr[0].BatchChannel

	go process(ctx, batchCh, msgCh, errCh)

	notBefore := time.Now().UTC()

	if err := injectBody(apiSrv, fixture.Inject.Path, fixture.Inject.Body); err != nil {
		glog.Errorf("inject failed: %v", err)
		os.Exit(1)
	}

	msg, err := waitForMessage(ctx, msgCh, errCh, notBefore, fixture.Observe.Match)
	if err != nil {
		glog.Errorf("failed to receive message: %v", err)
		os.Exit(1)
	}

	if glog.V(3) {
		glog.Infof("Received message: topic=%s partition=%d offset=%d timestamp=%s body=%s", msg.Topic, msg.Partition, msg.Offset, msg.Timestamp.Format(time.RFC3339), string(msg.Raw))
	}

	testErr := validateExpected(msg.Body, fixture.Expect)

	if fixture.Cleanup != nil {
		// For now just sleep for 60 seconds before clean up to check the router
		time.Sleep(time.Second * 60)

		if err := injectBody(apiSrv, fixture.Cleanup.Path, fixture.Cleanup.Body); err != nil {
			glog.Errorf("cleanup failed: %v", err)
			os.Exit(1)
		}
	}
	if testErr != nil {
		glog.Errorf("validation failed: %v", testErr)
		os.Exit(1)
	} else {
		glog.Infof("Test '%s' executed successfully", fixture.Name)
		os.Exit(0)
	}
}

func process(ctx context.Context, batchCh <-chan []kafka_consumer.Message, msgCh chan<- observedKafkaMessage, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			glog.Info("shutdown signal received")
			return

		case batch, ok := <-batchCh:
			if !ok {
				glog.Info("batch channel closed")
				select {
				case errCh <- fmt.Errorf("batch channel closed"):
				case <-ctx.Done():
				}
				return
			}

			// Process each message individually (not bulk) since we need Read-Modify-Write
			for _, msg := range batch {
				if len(msg.Msg.Value) == 0 {
					msg.AckCh <- fmt.Errorf("empty message value") // Acknowledge message even if we fail to process it to avoid blocking the consumer
					select {
					case errCh <- fmt.Errorf("empty message value"):
					case <-ctx.Done():
						return
					}
					continue
				}
				bmpMsg, err := decodeKafkaJSON(msg.Msg.Value)
				if err != nil {
					msg.AckCh <- fmt.Errorf("Failed to unmarshal Event message (len=%d): %v", len(msg.Msg.Value), err) // Acknowledge message even if we fail to process it to avoid blocking the consumer
					select {
					case errCh <- fmt.Errorf("Failed to unmarshal Event message (len=%d): %v", len(msg.Msg.Value), err):
					case <-ctx.Done():
						return
					}
					continue
				}
				ts := msg.Msg.Timestamp
				if ts.IsZero() {
					ts = time.Now()
				}
				msg.AckCh <- nil
				select {
				case msgCh <- observedKafkaMessage{
					Topic:     msg.Msg.Topic,
					Partition: msg.Msg.Partition,
					Offset:    msg.Msg.Offset,
					Body:      bmpMsg,
					Timestamp: ts.UTC(),
					Raw:       msg.Msg.Value,
				}:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func decodeKafkaJSON(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	var msg map[string]any
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func waitForMessage(ctx context.Context, msgCh <-chan observedKafkaMessage, errCh <-chan error, notBefore time.Time, match map[string]any) (observedKafkaMessage, error) {
messages:
	for {
		select {
		case <-ctx.Done():
			return observedKafkaMessage{}, fmt.Errorf("timeout waiting for message")
		case err := <-errCh:
			return observedKafkaMessage{}, fmt.Errorf("error from consumer: %v", err)
		case msg := <-msgCh:
			if msg.Timestamp.Before(notBefore) {
				continue // Ignore messages that were received before the injection
			}
			for k, v := range match {
				if msgVal, ok := msg.Body[k]; !ok || !valueEqual(msgVal, v) {
					continue messages // This message does not match the criteria, keep waiting
				}
			}
			return msg, nil
		}
	}
}

func matchSubset(actual, expected any) bool {
	switch exp := expected.(type) {
	case map[string]any:
		act, ok := actual.(map[string]any)
		if !ok {
			return false
		}
		for k, expVal := range exp {
			actVal, ok := act[k]
			if !ok || !matchSubset(actVal, expVal) {
				return false
			}
		}
		return true

	case []any:
		act, ok := actual.([]any)
		if !ok {
			return false
		}
		for _, expItem := range exp {
			found := false
			for _, actItem := range act {
				if matchSubset(actItem, expItem) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true

	default:
		return scalarEqual(actual, expected)
	}
}

func scalarEqual(actual, expected any) bool {
	if reflect.DeepEqual(actual, expected) {
		return true
	}

	av, aok := numberAsString(actual)
	ev, eok := numberAsString(expected)
	return aok && eok && av == ev
}

func numberAsString(v any) (string, bool) {
	switch x := v.(type) {
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case int:
		return strconv.Itoa(x), true
	case int64:
		return strconv.FormatInt(x, 10), true
	default:
		return "", false
	}
}

func valueEqual(actual, expected any) bool {
	switch exp := expected.(type) {
	case map[string]any:
		act, ok := actual.(map[string]any)
		if !ok || len(act) != len(exp) {
			return false
		}
		for k, expVal := range exp {
			actVal, ok := act[k]
			if !ok || !valueEqual(actVal, expVal) {
				return false
			}
		}
		return true

	case []any:
		act, ok := actual.([]any)
		if !ok || len(act) != len(exp) {
			return false
		}
		for i := range exp {
			if !valueEqual(act[i], exp[i]) {
				return false
			}
		}
		return true

	default:
		return scalarEqual(actual, expected)
	}
}

func validateExpected(msg map[string]any, expect ExpectSpec) error {
	if len(expect.Equals) > 0 {
		for k, v := range expect.Equals {
			if msgVal, ok := msg[k]; !ok || !valueEqual(msgVal, v) {
				return fmt.Errorf("expected equals: key=%s expected=%v got=%v", k, v, msgVal)
			}
		}
	}
	if len(expect.Contains) > 0 {
		for k, v := range expect.Contains {
			if msgVal, ok := msg[k]; !ok || !contains(msgVal, v) {
				return fmt.Errorf("expected contains: key=%s expected=%v got=%v", k, v, msgVal)
			}
		}
	}
	if len(expect.Present) > 0 {
		for _, k := range expect.Present {
			if _, ok := msg[k]; !ok {
				return fmt.Errorf("expected present: key=%s not found", k)
			}
		}
	}
	if len(expect.Absent) > 0 {
		for _, k := range expect.Absent {
			if _, ok := msg[k]; ok {
				return fmt.Errorf("expected absent: key=%s found", k)
			}
		}
	}
	return nil
}

func contains(msgVal, expected any) bool {
	return matchSubset(msgVal, expected)
}
