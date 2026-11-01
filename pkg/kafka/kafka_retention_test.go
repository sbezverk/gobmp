package kafka

import (
	"testing"

	"github.com/IBM/sarama"
)

// Exercise the public constructor and inspect decoded requests at the broker,
// rather than duplicating the TopicDetail construction in a test stub.
func TestNewKafkaPublisherTopicRetention(t *testing.T) {
	tests := []struct {
		name      string
		retention string
		skip      bool
		existing  bool
	}{
		{name: "unlimited", retention: "-1"},
		{name: "zero", retention: "0"},
		{name: "custom", retention: "123456"},
		{name: "default", retention: "900000"},
		{name: "existing topics", retention: "-1", existing: true},
		{name: "skip topic creation", retention: "-1", skip: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mb := sarama.NewMockBroker(t, 1)
			defer mb.Close()
			// MockCreateTopicsResponse supports TopicErrors through CreateTopics V4.
			apiVersions := sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
				{ApiKey: 0, MinVersion: 5, MaxVersion: 8},
				{ApiKey: 1, MinVersion: 7, MaxVersion: 11},
				{ApiKey: 3, MinVersion: 0, MaxVersion: 9},
				{ApiKey: 19, MinVersion: 0, MaxVersion: 4},
			})
			var topicResponse sarama.MockResponse = sarama.NewMockCreateTopicsResponse(t)
			if tt.existing {
				topicErrors := make(map[string]*sarama.TopicError, len(topicNames))
				for _, topic := range topicNames {
					topicErrors[WithTopicPrefix("retention-test", topic)] = &sarama.TopicError{Err: sarama.ErrTopicAlreadyExists}
				}
				topicResponse = sarama.NewMockWrapper(&sarama.CreateTopicsResponse{Version: 4, TopicErrors: topicErrors})
			}
			mb.SetHandlerByMap(map[string]sarama.MockResponse{
				"ApiVersionsRequest":  apiVersions,
				"MetadataRequest":     sarama.NewMockMetadataResponse(t).SetBroker(mb.Addr(), mb.BrokerID()).SetController(mb.BrokerID()),
				"CreateTopicsRequest": topicResponse,
				"ProduceRequest":      sarama.NewMockProduceResponse(t),
			})
			pub, err := NewKafkaPublisher(&Config{
				ServerAddress: mb.Addr(), TopicRetentionTimeMs: tt.retention,
				TopicPrefix: "retention-test", SkipTopicCreation: tt.skip,
			})
			if err != nil {
				t.Fatalf("NewKafkaPublisher(): %v", err)
			}
			defer pub.Stop()

			created := make(map[string]bool)
			for _, exchange := range mb.History() {
				switch request := exchange.Request.(type) {
				case *sarama.CreateTopicsRequest:
					for topic, detail := range request.TopicDetails {
						if detail.NumPartitions != 1 || detail.ReplicationFactor != 1 {
							t.Errorf("topic %s partitions/replicas = %d/%d, want 1/1", topic, detail.NumPartitions, detail.ReplicationFactor)
						}
						retention := detail.ConfigEntries["retention.ms"]
						if retention == nil {
							t.Errorf("topic %s is missing retention.ms", topic)
						} else if *retention != tt.retention {
							t.Errorf("topic %s retention.ms = %q, want %q", topic, *retention, tt.retention)
						}
						created[topic] = true
					}
				case *sarama.AlterConfigsRequest, *sarama.IncrementalAlterConfigsRequest:
					t.Errorf("unexpected configuration mutation: %T", request)
				}
			}
			if tt.skip {
				if len(created) != 0 {
					t.Errorf("created %d topics with SkipTopicCreation", len(created))
				}
				return
			}
			if len(created) != len(topicNames) {
				t.Errorf("CreateTopics covered %d topics, want %d", len(created), len(topicNames))
			}
			for _, topic := range topicNames {
				if !created[WithTopicPrefix("retention-test", topic)] {
					t.Errorf("missing CreateTopics for %s", topic)
				}
			}
		})
	}
}
