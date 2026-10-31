package kafka

import (
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

const legacyConsumerTestTimeout = 5 * time.Second

// Only the Sarama boundary is replaced; Start, topic readers, delivery and Stop
// remain the production implementation.
type legacyTestMaster struct {
	sarama.Consumer
	partitions func(string) ([]int32, error)
	consume    func(string, int32, int64) (sarama.PartitionConsumer, error)
	close      func() error
}

func (m *legacyTestMaster) Partitions(topic string) ([]int32, error) {
	return m.partitions(topic)
}

func (m *legacyTestMaster) ConsumePartition(topic string, partition int32, offset int64) (sarama.PartitionConsumer, error) {
	return m.consume(topic, partition, offset)
}

func (m *legacyTestMaster) Close() error {
	return m.close()
}

type legacyTestPartition struct {
	sarama.PartitionConsumer
	messages chan *sarama.ConsumerMessage
	errors   chan *sarama.ConsumerError
	close    func() error
}

func (p *legacyTestPartition) Messages() <-chan *sarama.ConsumerMessage {
	return p.messages
}

func (p *legacyTestPartition) Errors() <-chan *sarama.ConsumerError {
	return p.errors
}

func (p *legacyTestPartition) Close() error {
	return p.close()
}

func awaitLegacySignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(legacyConsumerTestTimeout):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func startLegacyTestConsumer(t *testing.T, k *kafka) func() {
	t.Helper()
	var once sync.Once
	stop := func() {
		t.Helper()
		once.Do(func() {
			stopped := make(chan struct{})
			go func() {
				k.Stop()
				close(stopped)
			}()
			awaitLegacySignal(t, stopped, "Stop")
		})
	}
	k.Start()
	t.Cleanup(stop)
	return stop
}

func startLegacyBrokerConsumer(t *testing.T, records map[int32][]string) (<-chan []byte, func()) {
	t.Helper()
	const topicName = "legacy-validator-test"
	broker := sarama.NewMockBroker(t, 1)
	t.Cleanup(broker.Close)
	metadata := sarama.NewMockMetadataResponse(t).
		SetBroker(broker.Addr(), broker.BrokerID())
	offsets := sarama.NewMockOffsetResponse(t)
	fetch := sarama.NewMockFetchResponse(t, 1000)
	for partition, values := range records {
		metadata.SetLeader(topicName, partition, broker.BrokerID())
		// A nonzero oldest offset proves that the existing OffsetOldest policy
		// is preserved rather than assuming a zero literal offset.
		const oldest = int64(17)
		offsets.SetOffset(topicName, partition, sarama.OffsetOldest, oldest).
			SetOffset(topicName, partition, sarama.OffsetNewest, oldest+int64(len(values)))
		for index, value := range values {
			fetch.SetMessage(topicName, partition, oldest+int64(index), sarama.StringEncoder(value))
		}
		fetch.SetHighWaterMark(topicName, partition, oldest+int64(len(values)))
	}
	broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest":    metadata,
		"OffsetRequest":      offsets,
		"FetchRequest":       fetch,
	})
	output := make(chan []byte)
	consumer, err := NewKafkaMConsumer(broker.Addr(), []*TopicDescriptor{{
		TopicName: topicName,
		TopicChan: output,
	}})
	if err != nil {
		t.Fatalf("NewKafkaMConsumer: %v", err)
	}
	var once sync.Once
	stop := func() {
		t.Helper()
		once.Do(func() {
			stopped := make(chan struct{})
			go func() {
				consumer.Stop()
				close(stopped)
			}()
			awaitLegacySignal(t, stopped, "public consumer Stop")
		})
	}
	consumer.Start()
	t.Cleanup(stop)
	return output, stop
}

func receiveLegacyMessage(t *testing.T, output <-chan []byte) string {
	t.Helper()
	select {
	case message := <-output:
		return string(message)
	case <-time.After(legacyConsumerTestTimeout):
		t.Fatal("timed out waiting for a Kafka record")
		return ""
	}
}
