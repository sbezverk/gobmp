package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/sbezverk/tools/kafka_consumer"
)

func validFixture() Fixture {
	return Fixture{
		SchemaVersion: 1,
		Name:          "ipv4-unicast",
		Inject: HTTPAction{
			Body: json.RawMessage(`{"routes":[{"prefix":"198.51.100.0/24","action":"announce"}]}`),
		},
		Observe: ObserveSpec{
			Source: "kafka",
			Topic:  "gobmp.parsed.unicast_prefix_v4",
			Match: map[string]any{
				"action": "add",
			},
		},
		Expect: ExpectSpec{
			NonEmpty: []string{"hash"},
		},
	}
}

func TestValidateAndNormalizeDefaults(t *testing.T) {
	f := validFixture()
	f.Name = " ipv4-unicast "
	f.Observe.Source = " kafka "
	f.Inject.Path = ""
	f.Cleanup = &HTTPAction{
		Body: json.RawMessage(`{"routes":[{"prefix":"198.51.100.0/24","action":"withdraw"}]}`),
	}

	if err := validateAndNormalize(&f); err != nil {
		t.Fatalf("validateAndNormalize returned error: %v", err)
	}
	if f.Name != "ipv4-unicast" {
		t.Fatalf("Name = %q, want trimmed name", f.Name)
	}
	if f.Inject.Path != injectPath {
		t.Fatalf("Inject.Path = %q, want %q", f.Inject.Path, injectPath)
	}
	if f.Cleanup.Path != injectPath {
		t.Fatalf("Cleanup.Path = %q, want %q", f.Cleanup.Path, injectPath)
	}
	if f.Observe.Source != "kafka" {
		t.Fatalf("Observe.Source = %q, want trimmed source", f.Observe.Source)
	}
	if f.Observe.timeoutSec != 120 {
		t.Fatalf("Observe.timeoutSec = %d, want 120", f.Observe.timeoutSec)
	}
}

func TestValidateAndNormalizeRejectsInvalidFixtures(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Fixture)
		wantErr string
	}{
		{
			name:    "schema",
			mutate:  func(f *Fixture) { f.SchemaVersion = 2 },
			wantErr: "unsupported schema version",
		},
		{
			name:    "name",
			mutate:  func(f *Fixture) { f.Name = " " },
			wantErr: "name is required",
		},
		{
			name:    "observe source",
			mutate:  func(f *Fixture) { f.Observe.Source = " " },
			wantErr: "observe.source is required",
		},
		{
			name:    "observe topic",
			mutate:  func(f *Fixture) { f.Observe.Topic = " " },
			wantErr: "observe.topic is required",
		},
		{
			name:    "bad timeout",
			mutate:  func(f *Fixture) { f.Observe.Timeout = "soon" },
			wantErr: "invalid observe.timeout",
		},
		{
			name:    "negative timeout",
			mutate:  func(f *Fixture) { f.Observe.Timeout = "0" },
			wantErr: "observe.timeout must be positive",
		},
		{
			name:    "bad inject body",
			mutate:  func(f *Fixture) { f.Inject.Body = json.RawMessage(`{"routes":`) },
			wantErr: "invalid inject.body",
		},
		{
			name:    "missing match",
			mutate:  func(f *Fixture) { f.Observe.Match = nil },
			wantErr: "observe.match is required",
		},
		{
			name:    "missing expect",
			mutate:  func(f *Fixture) { f.Expect = ExpectSpec{} },
			wantErr: "expect is required",
		},
		{
			name: "bad cleanup body",
			mutate: func(f *Fixture) {
				f.Cleanup = &HTTPAction{Body: json.RawMessage(`{"routes":`)}
			},
			wantErr: "invalid cleanup.body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFixture()
			tt.mutate(&f)

			err := validateAndNormalize(&f)
			if err == nil {
				t.Fatal("validateAndNormalize succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestInjectBodySuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != injectPath {
			t.Fatalf("path = %s, want %s", r.URL.Path, injectPath)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q, want application/json", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1,"updates":[{"prefix":"198.51.100.0/24","action":"announce","queued":true}]}`))
	}))
	defer server.Close()

	if err := injectBody(server.URL, injectPath, json.RawMessage(`{"routes":[]}`)); err != nil {
		t.Fatalf("injectBody returned error: %v", err)
	}
}

func TestInjectBodyFailures(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		response string
		wantErr  string
	}{
		{
			name:     "server error",
			status:   http.StatusInternalServerError,
			response: `boom`,
			wantErr:  "POST failed",
		},
		{
			name:     "invalid json",
			status:   http.StatusOK,
			response: `{`,
			wantErr:  "failed to decode response",
		},
		{
			name:     "accepted mismatch",
			status:   http.StatusOK,
			response: `{"accepted":2,"updates":[{"prefix":"198.51.100.0/24","action":"announce","queued":true}]}`,
			wantErr:  "inject not accepted",
		},
		{
			name:     "not queued",
			status:   http.StatusOK,
			response: `{"accepted":1,"updates":[{"prefix":"198.51.100.0/24","action":"announce","queued":false,"bytes":42}]}`,
			wantErr:  "injected update not queued",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.response))
			}))
			defer server.Close()

			err := injectBody(server.URL, injectPath, json.RawMessage(`{"routes":[]}`))
			if err == nil {
				t.Fatal("injectBody succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCheckSession(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("method = %s, want GET", r.Method)
			}
			if r.URL.Path != "/readyz" {
				t.Fatalf("path = %s, want /readyz", r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"state":"established"}`))
		}))
		defer server.Close()

		if err := checkSession(server.URL, "/readyz"); err != nil {
			t.Fatalf("checkSession returned error: %v", err)
		}
	})

	t.Run("bad status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		err := checkSession(server.URL, "/readyz")
		if err == nil || !strings.Contains(err.Error(), "GET failed") {
			t.Fatalf("checkSession error = %v, want GET failed", err)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer server.Close()

		err := checkSession(server.URL, "/readyz")
		if err == nil || !strings.Contains(err.Error(), "failed to decode response") {
			t.Fatalf("checkSession error = %v, want decode error", err)
		}
	})
}

func TestDecodeKafkaJSONUsesJSONNumber(t *testing.T) {
	msg, err := decodeKafkaJSON([]byte(`{"prefix_len":24,"prefix":"198.51.100.0"}`))
	if err != nil {
		t.Fatalf("decodeKafkaJSON returned error: %v", err)
	}
	if _, ok := msg["prefix_len"].(json.Number); !ok {
		t.Fatalf("prefix_len type = %T, want json.Number", msg["prefix_len"])
	}

	if _, err := decodeKafkaJSON([]byte(`{`)); err == nil {
		t.Fatal("decodeKafkaJSON succeeded for invalid JSON")
	}
}

func TestWaitForMessageSkipsOldAndMismatchedMessages(t *testing.T) {
	notBefore := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgCh := make(chan observedKafkaMessage, 3)
	errCh := make(chan error, 1)
	msgCh <- observedKafkaMessage{
		Timestamp: notBefore.Add(-time.Second),
		Body:      map[string]any{"action": "add", "prefix": "old"},
	}
	msgCh <- observedKafkaMessage{
		Timestamp: notBefore.Add(time.Millisecond),
		Body:      map[string]any{"action": "del", "prefix": "198.51.100.0"},
	}
	msgCh <- observedKafkaMessage{
		Timestamp: notBefore.Add(time.Millisecond),
		Offset:    7,
		Body:      map[string]any{"action": "add", "prefix": "198.51.100.0"},
	}

	got, err := waitForMessage(ctx, msgCh, errCh, notBefore, map[string]any{
		"action": "add",
		"prefix": "198.51.100.0",
	})
	if err != nil {
		t.Fatalf("waitForMessage returned error: %v", err)
	}
	if got.Offset != 7 {
		t.Fatalf("Offset = %d, want 7", got.Offset)
	}
}

func TestWaitForMessageReturnsConsumerError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msgCh := make(chan observedKafkaMessage)
	errCh := make(chan error, 1)
	errCh <- errors.New("consumer stopped")

	if _, err := waitForMessage(ctx, msgCh, errCh, time.Now(), map[string]any{"action": "add"}); err == nil {
		t.Fatal("waitForMessage succeeded, want consumer error")
	}
}

func TestWaitForMessageTimesOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	_, err := waitForMessage(ctx, make(chan observedKafkaMessage), make(chan error), time.Now(), map[string]any{"action": "add"})
	if err == nil || !strings.Contains(err.Error(), "timeout waiting for message") {
		t.Fatalf("waitForMessage error = %v, want timeout", err)
	}
}

func TestValidateExpectedContainsArrayField(t *testing.T) {
	msg := map[string]any{
		"labels": []any{json.Number("1000")},
	}
	expect := ExpectSpec{
		Contains: map[string]any{
			"labels": []any{json.Number("1000")},
		},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedContainsNestedMapSubset(t *testing.T) {
	msg := map[string]any{
		"base_attrs": map[string]any{
			"origin":               "igp",
			"as_path":              []any{json.Number("50123"), json.Number("64512"), json.Number("64513")},
			"community_list":       []any{"64512:100", "65535:65281"},
			"large_community_list": []any{"64512:10:100"},
			"med":                  json.Number("100"),
		},
	}
	expect := ExpectSpec{
		Contains: map[string]any{
			"base_attrs": map[string]any{
				"origin":         "igp",
				"as_path":        []any{json.Number("50123"), json.Number("64512"), json.Number("64513")},
				"community_list": []any{"64512:100"},
			},
		},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedEqualsRequiresFullArrayEquality(t *testing.T) {
	msg := map[string]any{
		"labels": []any{json.Number("1000"), json.Number("2000")},
	}
	expect := ExpectSpec{
		Equals: map[string]any{
			"labels": []any{json.Number("1000")},
		},
	}

	if err := validateExpected(msg, expect); err == nil {
		t.Fatal("validateExpected succeeded for partial array equality")
	}
}

func TestValidateExpectedPresentAbsentSupportNestedPaths(t *testing.T) {
	msg := map[string]any{
		"base_attrs": map[string]any{
			"base_attr_hash": "abc123",
		},
	}
	expect := ExpectSpec{
		Present: []string{"base_attrs.base_attr_hash"},
		Absent:  []string{"base_attrs.missing", "missing"},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedNonEmptySupportNestedPaths(t *testing.T) {
	msg := map[string]any{
		"hash": "prefix-hash",
		"base_attrs": map[string]any{
			"base_attr_hash": "attr-hash",
		},
	}
	expect := ExpectSpec{
		NonEmpty: []string{"hash", "base_attrs.base_attr_hash"},
	}

	if err := validateExpected(msg, expect); err != nil {
		t.Fatalf("validateExpected returned error: %v", err)
	}
}

func TestValidateExpectedNonEmptyRejectsEmptyValue(t *testing.T) {
	msg := map[string]any{
		"hash": "   ",
	}
	expect := ExpectSpec{
		NonEmpty: []string{"hash"},
	}

	if err := validateExpected(msg, expect); err == nil {
		t.Fatal("validateExpected succeeded for whitespace-only non_empty field")
	}
}

func TestValidateExpectedFailureBranches(t *testing.T) {
	msg := map[string]any{
		"action": "add",
		"hash":   "abc123",
		"base_attrs": map[string]any{
			"origin": "igp",
		},
	}
	tests := []struct {
		name    string
		expect  ExpectSpec
		wantErr string
	}{
		{
			name:    "equals missing",
			expect:  ExpectSpec{Equals: map[string]any{"missing": "value"}},
			wantErr: "expected equals",
		},
		{
			name:    "contains mismatch",
			expect:  ExpectSpec{Contains: map[string]any{"base_attrs": map[string]any{"origin": "egp"}}},
			wantErr: "expected contains",
		},
		{
			name:    "present missing",
			expect:  ExpectSpec{Present: []string{"base_attrs.base_attr_hash"}},
			wantErr: "expected present",
		},
		{
			name:    "non empty missing",
			expect:  ExpectSpec{NonEmpty: []string{"base_attrs.base_attr_hash"}},
			wantErr: "expected non-empty",
		},
		{
			name:    "absent found",
			expect:  ExpectSpec{Absent: []string{"hash"}},
			wantErr: "expected absent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExpected(msg, tt.expect)
			if err == nil {
				t.Fatal("validateExpected succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValueEqualNestedStructures(t *testing.T) {
	actual := map[string]any{
		"base_attrs": map[string]any{
			"as_path": []any{json.Number("50123"), json.Number("64512")},
			"med":     json.Number("100"),
		},
	}
	expected := map[string]any{
		"base_attrs": map[string]any{
			"as_path": []any{json.Number("50123"), json.Number("64512")},
			"med":     100,
		},
	}
	if !valueEqual(actual, expected) {
		t.Fatal("valueEqual returned false for equivalent nested structures")
	}

	if valueEqual(actual, map[string]any{"base_attrs": map[string]any{"as_path": []any{json.Number("50123")}}}) {
		t.Fatal("valueEqual returned true for different nested array length")
	}
	if valueEqual(actual, map[string]any{"base_attrs": []any{json.Number("50123")}}) {
		t.Fatal("valueEqual returned true for different nested type")
	}
	if valueEqual([]any{json.Number("1")}, []any{json.Number("2")}) {
		t.Fatal("valueEqual returned true for different arrays")
	}
	if valueEqual([]any{json.Number("1")}, "1") {
		t.Fatal("valueEqual returned true for array vs scalar")
	}
}

func TestMatchSubsetFailureBranches(t *testing.T) {
	if matchSubset("not-a-map", map[string]any{"origin": "igp"}) {
		t.Fatal("matchSubset returned true for non-map actual")
	}
	if matchSubset(map[string]any{"origin": "igp"}, map[string]any{"missing": "igp"}) {
		t.Fatal("matchSubset returned true for missing map key")
	}
	if matchSubset("not-array", []any{"igp"}) {
		t.Fatal("matchSubset returned true for non-array actual")
	}
	if matchSubset([]any{"igp"}, []any{"egp"}) {
		t.Fatal("matchSubset returned true for missing array item")
	}
}

func TestNumberAndEmptyHelpers(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
		ok   bool
	}{
		{name: "json number", in: json.Number("100"), want: "100", ok: true},
		{name: "float64", in: float64(100), want: "100", ok: true},
		{name: "int", in: int(100), want: "100", ok: true},
		{name: "int64", in: int64(100), want: "100", ok: true},
		{name: "string", in: "100", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := numberAsString(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("numberAsString(%v) = %q/%v, want %q/%v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}

	for _, v := range []any{nil, "", "   ", []any{}, map[string]any{}} {
		if !isEmptyValue(v) {
			t.Fatalf("isEmptyValue(%#v) = false, want true", v)
		}
	}
	for _, v := range []any{"hash", []any{"x"}, map[string]any{"x": "y"}, 42} {
		if isEmptyValue(v) {
			t.Fatalf("isEmptyValue(%#v) = true, want false", v)
		}
	}
}

func TestValueAtPathFailures(t *testing.T) {
	msg := map[string]any{
		"base_attrs": map[string]any{"origin": "igp"},
		"hash":       "abc",
	}
	for _, path := range []string{"", "base_attrs.missing", "hash.value"} {
		if _, ok := valueAtPath(msg, path); ok {
			t.Fatalf("valueAtPath(%q) ok = true, want false", path)
		}
	}
}

func TestProcessDecodesKafkaBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	batchCh := make(chan []kafka_consumer.Message, 1)
	msgCh := make(chan observedKafkaMessage, 1)
	errCh := make(chan error, 1)
	go process(ctx, batchCh, msgCh, errCh)

	ts := time.Now().UTC()
	ackCh := make(chan error, 1)
	batchCh <- []kafka_consumer.Message{{
		Msg: &sarama.ConsumerMessage{
			Topic:     "gobmp.parsed.unicast_prefix_v4",
			Partition: 3,
			Offset:    42,
			Timestamp: ts,
			Value:     []byte(`{"action":"add","prefix_len":24}`),
		},
		AckCh: ackCh,
	}}

	if err := <-ackCh; err != nil {
		t.Fatalf("ack error = %v, want nil", err)
	}
	got := <-msgCh
	if got.Topic != "gobmp.parsed.unicast_prefix_v4" {
		t.Fatalf("Topic = %q, want gobmp.parsed.unicast_prefix_v4", got.Topic)
	}
	if got.Partition != 3 || got.Offset != 42 {
		t.Fatalf("partition/offset = %d/%d, want 3/42", got.Partition, got.Offset)
	}
	if _, ok := got.Body["prefix_len"].(json.Number); !ok {
		t.Fatalf("prefix_len type = %T, want json.Number", got.Body["prefix_len"])
	}
}

func TestProcessReportsEmptyAndInvalidMessages(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
	}{
		{name: "empty"},
		{name: "invalid json", value: []byte(`{`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			batchCh := make(chan []kafka_consumer.Message, 1)
			msgCh := make(chan observedKafkaMessage, 1)
			errCh := make(chan error, 1)
			go process(ctx, batchCh, msgCh, errCh)

			ackCh := make(chan error, 1)
			batchCh <- []kafka_consumer.Message{{
				Msg: &sarama.ConsumerMessage{
					Value: tt.value,
				},
				AckCh: ackCh,
			}}

			if err := <-ackCh; err == nil {
				t.Fatal("ack error = nil, want error")
			}
			if err := <-errCh; err == nil {
				t.Fatal("errCh returned nil, want error")
			}
		})
	}
}

func TestProcessReportsClosedBatchChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	batchCh := make(chan []kafka_consumer.Message)
	msgCh := make(chan observedKafkaMessage, 1)
	errCh := make(chan error, 1)
	go process(ctx, batchCh, msgCh, errCh)
	close(batchCh)

	err := <-errCh
	if err == nil || !strings.Contains(err.Error(), "batch channel closed") {
		t.Fatalf("errCh = %v, want batch channel closed", err)
	}
}
