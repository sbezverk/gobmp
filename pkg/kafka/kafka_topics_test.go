package kafka

import (
	"testing"

	"github.com/IBM/sarama"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// captureAsyncProducer lets PublishMessage be tested without a Kafka broker.
// The embedded interface supplies methods that this routing test does not use.
type captureAsyncProducer struct {
	sarama.AsyncProducer
	input chan *sarama.ProducerMessage
}

func (p *captureAsyncProducer) Input() chan<- *sarama.ProducerMessage {
	return p.input
}

func TestPublishMessageMUPTopics(t *testing.T) {
	tests := []struct {
		name    string
		msgType int
		topic   string
	}{
		{name: "combined", msgType: bmp.MUPMsg, topic: MUPMessageTopic},
		{name: "IPv4", msgType: bmp.MUPV4Msg, topic: MUPMessageV4Topic},
		{name: "IPv6", msgType: bmp.MUPV6Msg, topic: MUPMessageV6Topic},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer := &captureAsyncProducer{
				input: make(chan *sarama.ProducerMessage, 1),
			}
			p := &publisher{
				producer:    producer,
				topicPrefix: "test",
			}

			if err := p.PublishMessage(tt.msgType, []byte("key"), []byte("message")); err != nil {
				t.Fatalf("PublishMessage() unexpected error: %v", err)
			}

			msg := <-producer.input
			if got, want := msg.Topic, "test."+tt.topic; got != want {
				t.Fatalf("PublishMessage() topic = %q, want %q", got, want)
			}
		})
	}
}

func TestTopicForMessageUnknown(t *testing.T) {
	if topic, ok := topicForMessage(9999); ok || topic != "" {
		t.Fatalf("topicForMessage() = %q, %t; want empty topic and false", topic, ok)
	}
}
