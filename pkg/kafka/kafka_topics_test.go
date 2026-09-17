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

func TestPublishMessageTopics(t *testing.T) {
	tests := []struct {
		name    string
		msgType int
		topic   string
	}{
		{name: "peer", msgType: bmp.PeerStateChangeMsg, topic: PeerTopic},
		{name: "unicast", msgType: bmp.UnicastPrefixMsg, topic: UnicastMessageTopic},
		{name: "unicast IPv4", msgType: bmp.UnicastPrefixV4Msg, topic: UnicastMessageV4Topic},
		{name: "unicast IPv6", msgType: bmp.UnicastPrefixV6Msg, topic: UnicastMessageV6Topic},
		{name: "LS node", msgType: bmp.LSNodeMsg, topic: LSNodeMessageTopic},
		{name: "LS link", msgType: bmp.LSLinkMsg, topic: LSLinkMessageTopic},
		{name: "L3VPN", msgType: bmp.L3VPNMsg, topic: L3vpnMessageTopic},
		{name: "L3VPN IPv4", msgType: bmp.L3VPNV4Msg, topic: L3vpnMessageV4Topic},
		{name: "L3VPN IPv6", msgType: bmp.L3VPNV6Msg, topic: L3vpnMessageV6Topic},
		{name: "LS prefix", msgType: bmp.LSPrefixMsg, topic: LSPrefixMessageTopic},
		{name: "LS SRv6 SID", msgType: bmp.LSSRv6SIDMsg, topic: LSSRv6SIDMessageTopic},
		{name: "EVPN", msgType: bmp.EVPNMsg, topic: EVPNMessageTopic},
		{name: "SR policy", msgType: bmp.SRPolicyMsg, topic: SRPolicyMessageTopic},
		{name: "SR policy IPv4", msgType: bmp.SRPolicyV4Msg, topic: SRPolicyMessageV4Topic},
		{name: "SR policy IPv6", msgType: bmp.SRPolicyV6Msg, topic: SRPolicyMessageV6Topic},
		{name: "FlowSpec", msgType: bmp.FlowspecMsg, topic: FlowspecMessageTopic},
		{name: "FlowSpec IPv4", msgType: bmp.FlowspecV4Msg, topic: FlowspecMessageV4Topic},
		{name: "FlowSpec IPv6", msgType: bmp.FlowspecV6Msg, topic: FlowspecMessageV6Topic},
		{name: "VPLS", msgType: bmp.VPLSMsg, topic: VPLSMessageTopic},
		{name: "combined", msgType: bmp.MUPMsg, topic: MUPMessageTopic},
		{name: "IPv4", msgType: bmp.MUPV4Msg, topic: MUPMessageV4Topic},
		{name: "IPv6", msgType: bmp.MUPV6Msg, topic: MUPMessageV6Topic},
		{name: "statistics", msgType: bmp.StatsReportMsg, topic: StatsMessageTopic},
		{name: "raw", msgType: bmp.BMPRawMsg, topic: RawMessageTopic},
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

func TestPublishMessageUnsupported(t *testing.T) {
	producer := &captureAsyncProducer{
		input: make(chan *sarama.ProducerMessage, 1),
	}
	p := &publisher{producer: producer}

	if err := p.PublishMessage(9999, []byte("key"), []byte("message")); err == nil {
		t.Fatal("PublishMessage() error = nil, want an error for an unsupported message type")
	}
}

func TestTopicForMessageUnknown(t *testing.T) {
	if topic, ok := topicForMessage(9999); ok || topic != "" {
		t.Fatalf("topicForMessage() = %q, %t; want empty topic and false", topic, ok)
	}
}
