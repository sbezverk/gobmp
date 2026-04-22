package nats

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestTopicForMessage(t *testing.T) {
	tests := []struct {
		msgType   int
		wantTopic string
		wantOK    bool
	}{
		{bmp.PeerStateChangeMsg, peerTopic, true},
		{bmp.UnicastPrefixMsg, unicastMessageTopic, true},
		{bmp.UnicastPrefixV4Msg, unicastMessageV4Topic, true},
		{bmp.UnicastPrefixV6Msg, unicastMessageV6Topic, true},
		{bmp.LSNodeMsg, lsNodeMessageTopic, true},
		{bmp.LSLinkMsg, lsLinkMessageTopic, true},
		{bmp.L3VPNMsg, l3vpnMessageTopic, true},
		{bmp.L3VPNV4Msg, l3vpnMessageV4Topic, true},
		{bmp.L3VPNV6Msg, l3vpnMessageV6Topic, true},
		{bmp.LSPrefixMsg, lsPrefixMessageTopic, true},
		{bmp.LSSRv6SIDMsg, lsSRv6SIDMessageTopic, true},
		{bmp.EVPNMsg, evpnMessageTopic, true},
		{bmp.SRPolicyMsg, srPolicyMessageTopic, true},
		{bmp.SRPolicyV4Msg, srPolicyMessageV4Topic, true},
		{bmp.SRPolicyV6Msg, srPolicyMessageV6Topic, true},
		{bmp.FlowspecMsg, flowspecMessageTopic, true},
		{bmp.FlowspecV4Msg, flowspecMessageV4Topic, true},
		{bmp.FlowspecV6Msg, flowspecMessageV6Topic, true},
		{bmp.VPLSMsg, vplsMessageTopic, true},
		{bmp.StatsReportMsg, statsMessageTopic, true},
		{bmp.BMPRawMsg, rawMessageTopic, true},
		{9999, "", false},
	}

	for _, tt := range tests {
		topic, ok := topicForMessage(tt.msgType)
		if ok != tt.wantOK {
			t.Errorf("topicForMessage(%d): ok=%v, want %v", tt.msgType, ok, tt.wantOK)
			continue
		}
		if topic != tt.wantTopic {
			t.Errorf("topicForMessage(%d): topic=%q, want %q", tt.msgType, topic, tt.wantTopic)
		}
	}
}

func TestRawTopicNotUnderParsedWildcard(t *testing.T) {
	// gobmp.raw must be explicitly added to the stream Subjects because the
	// gobmp.parsed.* wildcard only matches three-segment subjects. Assert
	// the exact subject so accidental renames (e.g., to gobmp.parsed.raw)
	// are caught rather than silently drifting from the Kafka topic.
	if rawMessageTopic != "gobmp.raw" {
		t.Errorf("rawMessageTopic=%q, want %q (Kafka parity); stream config covers it explicitly", rawMessageTopic, "gobmp.raw")
	}
	topic, ok := topicForMessage(bmp.BMPRawMsg)
	if !ok || topic != rawMessageTopic {
		t.Errorf("BMPRawMsg must map to rawMessageTopic, got %q ok=%v", topic, ok)
	}
}
