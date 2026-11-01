package kafka

import (
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

// Use a real admin so the assertions cover the conversion and wire encoding.
func topicSpecTestAdmin(t *testing.T, response sarama.MockResponse) (sarama.ClusterAdmin, *sarama.MockBroker, time.Duration) {
	t.Helper()
	mb := sarama.NewMockBroker(t, 1)
	t.Cleanup(mb.Close)
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
			{ApiKey: 3, MinVersion: 0, MaxVersion: 9},
			{ApiKey: 19, MinVersion: 0, MaxVersion: 4},
		}),
		"MetadataRequest":     sarama.NewMockMetadataResponse(t).SetBroker(mb.Addr(), mb.BrokerID()).SetController(mb.BrokerID()),
		"CreateTopicsRequest": response,
	})
	config := sarama.NewConfig()
	config.Version = sarama.V3_0_0_0
	config.Admin.Retry.Max = 0
	config.Admin.Timeout = 3 * time.Second
	ca, err := sarama.NewClusterAdmin([]string{mb.Addr()}, config)
	if err != nil {
		t.Fatalf("NewClusterAdmin(): %v", err)
	}
	t.Cleanup(func() {
		if err := ca.Close(); err != nil {
			t.Errorf("ClusterAdmin.Close(): %v", err)
		}
	})
	return ca, mb, config.Admin.Timeout
}

func TestEnsureTopicSpecs(t *testing.T) {
	ca, mb, adminTimeout := topicSpecTestAdmin(t, sarama.NewMockCreateTopicsResponse(t))
	specs := []*TopicSpec{
		{Name: "spec.first", NumPartitions: 3, ReplicationFactor: 2, ConfigEntries: map[string]string{
			"retention.ms": "123456", "cleanup.policy": "compact", "compression.type": "",
		}},
		{Name: "spec.second", NumPartitions: 7, ReplicationFactor: 3, ConfigEntries: map[string]string{
			"retention.ms": "-1", "cleanup.policy": "delete", "segment.bytes": "4096",
		}},
		{Name: "spec.broker-defaults", NumPartitions: -1, ReplicationFactor: -1},
		{Name: "spec.empty-config", NumPartitions: 2, ReplicationFactor: 1, ConfigEntries: map[string]string{}},
	}
	want := make(map[string]TopicSpec, len(specs))
	for _, spec := range specs {
		want[spec.Name] = TopicSpec{
			Name: spec.Name, NumPartitions: spec.NumPartitions, ReplicationFactor: spec.ReplicationFactor,
			ConfigEntries: maps.Clone(spec.ConfigEntries),
		}
	}
	if err := ensureTopic(ca, time.Second, nil); err == nil || !strings.Contains(err.Error(), "nil TopicSpec") {
		t.Fatalf("ensureTopic(nil spec) = %v, want clear nil TopicSpec error", err)
	}
	for _, spec := range specs {
		if err := ensureTopic(ca, time.Second, spec); err != nil {
			t.Fatalf("ensureTopic(%s): %v", spec.Name, err)
		}
		if !reflect.DeepEqual(*spec, want[spec.Name]) {
			t.Errorf("input spec changed: got %+v, want %+v", *spec, want[spec.Name])
		}
	}
	seen := make(map[string]int)
	requests := 0
	for _, exchange := range mb.History() {
		request, ok := exchange.Request.(*sarama.CreateTopicsRequest)
		if !ok {
			continue
		}
		requests++
		if request.Timeout != adminTimeout || request.ValidateOnly || len(request.TopicDetails) != 1 {
			t.Errorf("unexpected CreateTopics envelope: %+v", request)
		}
		for name, detail := range request.TopicDetails {
			expected, ok := want[name]
			if !ok {
				t.Errorf("unexpected topic %q", name)
				continue
			}
			seen[name]++
			if detail.NumPartitions != expected.NumPartitions || detail.ReplicationFactor != expected.ReplicationFactor {
				t.Errorf("%s partitions/replicas = %d/%d, want %d/%d", name, detail.NumPartitions, detail.ReplicationFactor, expected.NumPartitions, expected.ReplicationFactor)
			}
			if len(detail.ReplicaAssignment) != 0 || len(detail.ConfigEntries) != len(expected.ConfigEntries) {
				t.Errorf("%s unexpected assignments/configs: %+v", name, detail)
			}
			for key, value := range expected.ConfigEntries {
				if got := detail.ConfigEntries[key]; got == nil || *got != value {
					t.Errorf("%s config %s = %v, want %q", name, key, got, value)
				}
			}
		}
	}
	if requests != len(specs) {
		t.Errorf("CreateTopics requests = %d, want %d (nil spec must send none)", requests, len(specs))
	}
	for name := range want {
		if seen[name] != 1 {
			t.Errorf("topic %s created %d times, want once", name, seen[name])
		}
	}
}

func TestEnsureTopicResponses(t *testing.T) {
	const topic = "spec.responses"
	response := func(code sarama.KError) *sarama.CreateTopicsResponse {
		return &sarama.CreateTopicsResponse{Version: 4, TopicErrors: map[string]*sarama.TopicError{topic: {Err: code}}}
	}
	tests := []struct {
		name     string
		response sarama.MockResponse
		timeout  time.Duration
		wantErr  error
		wantText string
		requests int
	}{
		{name: "success", response: sarama.NewMockWrapper(response(sarama.ErrNoError)), requests: 1},
		{name: "already exists", response: sarama.NewMockWrapper(response(sarama.ErrTopicAlreadyExists)), requests: 1},
		{name: "incomplete", response: sarama.NewMockWrapper(&sarama.CreateTopicsResponse{Version: 4}), wantErr: sarama.ErrIncompleteResponse, requests: 1},
		{name: "authorization", response: sarama.NewMockWrapper(response(sarama.ErrTopicAuthorizationFailed)), wantErr: sarama.ErrTopicAuthorizationFailed, requests: 1},
		{name: "retry then success", response: sarama.NewMockSequence(response(sarama.ErrRequestTimedOut), response(sarama.ErrNoError)), requests: 2},
		{name: "retry timeout", response: sarama.NewMockWrapper(response(sarama.ErrRequestTimedOut)), timeout: time.Millisecond, wantText: "timeout waiting for topic " + topic, requests: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca, mb, adminTimeout := topicSpecTestAdmin(t, tt.response)
			timeout := tt.timeout
			if timeout == 0 {
				timeout = time.Second
			}
			err := ensureTopic(ca, timeout, &TopicSpec{Name: topic, NumPartitions: 2, ReplicationFactor: 1})
			if tt.wantText != "" {
				if err == nil || err.Error() != tt.wantText {
					t.Errorf("ensureTopic() = %v, want %q", err, tt.wantText)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Errorf("ensureTopic() = %v, want %v", err, tt.wantErr)
			}
			requests := 0
			for _, exchange := range mb.History() {
				if request, ok := exchange.Request.(*sarama.CreateTopicsRequest); ok {
					requests++
					if request.Timeout != adminTimeout {
						t.Errorf("wire timeout = %v, want admin timeout %v (operation timeout %v)", request.Timeout, adminTimeout, timeout)
					}
				}
			}
			if requests != tt.requests {
				t.Errorf("CreateTopics requests = %d, want %d", requests, tt.requests)
			}
		})
	}
}
