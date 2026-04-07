package message

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func statsTestPeerHeader() *bmp.PerPeerHeader {
	return &bmp.PerPeerHeader{
		PeerAS:            65001,
		PeerType:          0,
		PeerBGPID:         make([]byte, 4),
		PeerAddress:       make([]byte, 16),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}
}

// TestProduceStatsMessage_AllTypes exercises produceStatsMessage with all stat types
func TestProduceStatsMessage_AllTypes(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}

	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 0, InformationLength: 4, Information: uint32Bytes(100)},
			{InformationType: 1, InformationLength: 4, Information: uint32Bytes(200)},
			{InformationType: 2, InformationLength: 4, Information: uint32Bytes(300)},
			{InformationType: 3, InformationLength: 4, Information: uint32Bytes(400)},
			{InformationType: 4, InformationLength: 4, Information: uint32Bytes(500)},
			{InformationType: 5, InformationLength: 4, Information: uint32Bytes(600)},
			{InformationType: 6, InformationLength: 4, Information: uint32Bytes(700)},
			{InformationType: 7, InformationLength: 8, Information: uint64Bytes(800)},
			{InformationType: 8, InformationLength: 8, Information: uint64Bytes(900)},
			{InformationType: 9, InformationLength: 11, Information: makeAFISAFIData(1, 1, 1000)},
			{InformationType: 10, InformationLength: 11, Information: makeAFISAFIData(2, 1, 1100)},
			{InformationType: 11, InformationLength: 4, Information: uint32Bytes(1200)},
			{InformationType: 12, InformationLength: 4, Information: uint32Bytes(1300)},
			{InformationType: 13, InformationLength: 4, Information: uint32Bytes(1400)},
			{InformationType: 14, InformationLength: 8, Information: uint64Bytes(1500)},
			{InformationType: 15, InformationLength: 8, Information: uint64Bytes(1600)},
			{InformationType: 16, InformationLength: 11, Information: makeAFISAFIData(1, 128, 1700)},
			{InformationType: 17, InformationLength: 11, Information: makeAFISAFIData(2, 128, 1800)},
		},
	}

	msg := bmp.Message{
		PeerHeader: statsTestPeerHeader(),
		Payload:    statsMsg,
	}

	// Should not panic
	p.produceStatsMessage(msg)
}

// TestProduceStatsMessage_TruncatedUint32 exercises the length guard for 4-byte stats
func TestProduceStatsMessage_TruncatedUint32(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}

	for _, statType := range []uint16{0, 1, 2, 3, 4, 5, 6, 11, 12, 13} {
		statsMsg := &bmp.StatsReport{
			StatsTLV: []bmp.InformationalTLV{
				{InformationType: statType, InformationLength: 2, Information: []byte{0x00, 0x01}},
			},
		}
		msg := bmp.Message{
			PeerHeader: statsTestPeerHeader(),
			Payload:    statsMsg,
		}
		// Should not panic on truncated data
		p.produceStatsMessage(msg)
	}
}

// TestProduceStatsMessage_TruncatedUint64 exercises the length guard for 8-byte stats
func TestProduceStatsMessage_TruncatedUint64(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}

	for _, statType := range []uint16{7, 8, 14, 15} {
		statsMsg := &bmp.StatsReport{
			StatsTLV: []bmp.InformationalTLV{
				{InformationType: statType, InformationLength: 3, Information: []byte{0x00, 0x01, 0x02}},
			},
		}
		msg := bmp.Message{
			PeerHeader: statsTestPeerHeader(),
			Payload:    statsMsg,
		}
		// Should not panic on truncated data
		p.produceStatsMessage(msg)
	}
}

// TestProduceStatsMessage_NilPeerHeader exercises the nil PeerHeader guard
func TestProduceStatsMessage_NilPeerHeader(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}
	msg := bmp.Message{
		PeerHeader: nil,
		Payload:    &bmp.StatsReport{},
	}
	p.produceStatsMessage(msg)
}

// TestProduceStatsMessage_InvalidPayload exercises the type assertion guard
func TestProduceStatsMessage_InvalidPayload(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}
	msg := bmp.Message{
		PeerHeader: statsTestPeerHeader(),
		Payload:    "not a StatsReport",
	}
	p.produceStatsMessage(msg)
}

// TestProduceStatsMessage_EmptyTLV exercises the empty TLV guard
func TestProduceStatsMessage_EmptyTLV(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}
	msg := bmp.Message{
		PeerHeader: statsTestPeerHeader(),
		Payload:    &bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{}},
	}
	p.produceStatsMessage(msg)
}

// TestProduceStatsMessage_UnknownType exercises the default case
func TestProduceStatsMessage_UnknownType(t *testing.T) {
	p := &producer{
		transportHash: "test-hash",
		transportIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 255, InformationLength: 4, Information: uint32Bytes(999)},
		},
	}
	msg := bmp.Message{
		PeerHeader: statsTestPeerHeader(),
		Payload:    statsMsg,
	}
	p.produceStatsMessage(msg)
}

func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
