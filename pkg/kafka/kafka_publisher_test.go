package kafka

import (
	"testing"
	"time"

	"github.com/IBM/sarama"
)

func TestValidator(t *testing.T) {
	const validRetention = "900000"
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: validRetention},
			wantErr: false,
		},
		{
			name:    "valid config with skip topic creation",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: validRetention, SkipTopicCreation: true},
			wantErr: false,
		},
		{
			name:    "missing port",
			cfg:     &Config{ServerAddress: "127.0.0.1", TopicRetentionTimeMs: validRetention},
			wantErr: true,
		},
		{
			name:    "empty host",
			cfg:     &Config{ServerAddress: ":9092", TopicRetentionTimeMs: validRetention},
			wantErr: true,
		},
		{
			name:    "invalid retention",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "not-a-number"},
			wantErr: true,
		},
		{
			name:    "retention below -1",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "-2"},
			wantErr: true,
		},
		{
			name:    "retention -1 is allowed",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "-1"},
			wantErr: false,
		},
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("validator() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestNewKafkaPublisher_WithTopicCreation exercises the default (SkipTopicCreation=false)
// path: ClusterAdmin and waitForControllerBrokerConnection succeed via mock, then
// ensureTopic fails fast (mock has no CreateTopicsRequest handler; netReadTimeout
// causes a quick read timeout; adminRetryMax=0 skips retries). All non-skip path
// lines in NewKafkaPublisher are exercised.
func TestNewKafkaPublisher_WithTopicCreation(t *testing.T) {
	origRetry := adminRetryMax
	origTimeout := netReadTimeout
	adminRetryMax = 0
	netReadTimeout = 200 * time.Millisecond
	defer func() {
		adminRetryMax = origRetry
		netReadTimeout = origTimeout
	}()

	mb := sarama.NewMockBroker(t, 1)
	defer mb.Close()
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(mb.Addr(), mb.BrokerID()).
			SetController(mb.BrokerID()),
		// No CreateTopicsRequest handler: mock ignores it, read timeout fires.
	})

	cfg := &Config{
		ServerAddress:        mb.Addr(),
		TopicRetentionTimeMs: "900000",
		SkipTopicCreation:    false,
	}
	_, err := NewKafkaPublisher(cfg)
	if err == nil {
		t.Fatal("expected error from topic creation timeout, got nil")
	}
}

// TestNewKafkaPublisher_WithTopicCreation_Success exercises the default
// (SkipTopicCreation=false) happy path: ClusterAdmin creates all topics
// successfully via mock broker, then an async producer is returned.
func TestNewKafkaPublisher_WithTopicCreation_Success(t *testing.T) {
	mb := sarama.NewMockBroker(t, 1)
	defer mb.Close()
	// Cap CreateTopics (API key 19) at V4 so MockCreateTopicsResponse works;
	// V5+ requires TopicResults which the mock doesn't populate.
	apiVersions := sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
		{ApiKey: 0, MinVersion: 5, MaxVersion: 8},  // Produce
		{ApiKey: 1, MinVersion: 7, MaxVersion: 11}, // Fetch
		{ApiKey: 3, MinVersion: 0, MaxVersion: 9},  // Metadata
		{ApiKey: 19, MinVersion: 0, MaxVersion: 4}, // CreateTopics
	})
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": apiVersions,
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(mb.Addr(), mb.BrokerID()).
			SetController(mb.BrokerID()),
		"CreateTopicsRequest": sarama.NewMockCreateTopicsResponse(t),
		"ProduceRequest":      sarama.NewMockProduceResponse(t),
	})

	cfg := &Config{
		ServerAddress:        mb.Addr(),
		TopicRetentionTimeMs: "900000",
		SkipTopicCreation:    false,
	}
	pub, err := NewKafkaPublisher(cfg)
	if err != nil {
		t.Fatalf("NewKafkaPublisher with SkipTopicCreation=false: %v", err)
	}
	pub.Stop()
}

// TestNewKafkaPublisher_SkipTopicCreation exercises the SkipTopicCreation=true
// path using an in-memory mock broker: ClusterAdmin init and ensureTopic are
// bypassed; the async producer connects successfully and Stop() closes cleanly.
func TestNewKafkaPublisher_SkipTopicCreation(t *testing.T) {
	mb := sarama.NewMockBroker(t, 1)
	defer mb.Close()
	mb.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(mb.Addr(), mb.BrokerID()),
		"ProduceRequest": sarama.NewMockProduceResponse(t),
	})

	cfg := &Config{
		ServerAddress:        mb.Addr(),
		TopicRetentionTimeMs: "900000",
		SkipTopicCreation:    true,
	}
	pub, err := NewKafkaPublisher(cfg)
	if err != nil {
		t.Fatalf("NewKafkaPublisher with SkipTopicCreation=true: %v", err)
	}
	pub.Stop()
}

// stubAdmin is a minimal sarama.ClusterAdmin that only implements Close and
// records whether Close was called.
type stubAdmin struct {
	sarama.ClusterAdmin
	closed bool
}

func (s *stubAdmin) Close() error {
	s.closed = true
	return nil
}

type nilControllerAdmin struct {
	sarama.ClusterAdmin
}

func (n *nilControllerAdmin) Controller() (*sarama.Broker, error) {
	return nil, nil
}

// TestStop_NilClusterAdmin verifies Stop() does not panic when clusterAdmin is nil.
func TestStop_NilClusterAdmin(t *testing.T) {
	stopCh := make(chan struct{})
	p := &publisher{clusterAdmin: nil, stopCh: stopCh}
	p.Stop()
	select {
	case <-stopCh:
	default:
		t.Error("Stop() did not close stopCh")
	}
}

// TestStop_NonNilClusterAdmin verifies Stop() calls Close on a non-nil clusterAdmin.
func TestStop_NonNilClusterAdmin(t *testing.T) {
	stopCh := make(chan struct{})
	sa := &stubAdmin{}
	p := &publisher{clusterAdmin: sa, stopCh: stopCh}
	p.Stop()
	select {
	case <-stopCh:
	default:
		t.Error("Stop() did not close stopCh")
	}
	if !sa.closed {
		t.Error("Stop() did not call Close on clusterAdmin")
	}
}

func TestEnsureTopic_NilClusterAdmin(t *testing.T) {
	err := ensureTopic(nil, time.Millisecond, PeerTopic)
	if err == nil {
		t.Fatal("ensureTopic(nil) error = nil, want error")
	}
}

func TestWaitForControllerBrokerConnection_NilController(t *testing.T) {
	_, err := waitForControllerBrokerConnection(&nilControllerAdmin{}, nil, time.Millisecond)
	if err == nil {
		t.Fatal("waitForControllerBrokerConnection() error = nil, want error")
	}
}
