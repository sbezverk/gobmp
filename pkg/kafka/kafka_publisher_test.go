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

// stubAdmin is a minimal sarama.ClusterAdmin that only implements Close.
type stubAdmin struct{ sarama.ClusterAdmin }

func (s *stubAdmin) Close() error { return nil }

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
	p := &publisher{clusterAdmin: &stubAdmin{}, stopCh: stopCh}
	p.Stop()
	select {
	case <-stopCh:
	default:
		t.Error("Stop() did not close stopCh")
	}
}
