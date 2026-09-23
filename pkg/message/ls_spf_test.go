package message

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
)

type lsSPFTLV struct {
	typeID uint16
	value  []byte
}

type lsSPFMockNLRI struct {
	bgp.MPNLRI
	nlri    *ls.NLRI71
	err     error
	nextHop string
}

func (m lsSPFMockNLRI) GetNLRI80() (*ls.NLRI71, error) {
	return m.nlri, m.err
}

func (m lsSPFMockNLRI) GetNextHop() string { return m.nextHop }

type lsSPFNoGetter struct{ bgp.MPNLRI }

func testLSNodeDescriptor() *base.NodeDescriptor {
	return &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
		512: {Type: 512, Length: 4, Value: []byte{0, 0, 0xfd, 0xe8}},
		516: {Type: 516, Length: 4, Value: []byte{192, 0, 2, 1}},
	}}
}

func testLSNode(protocol base.ProtoID) *base.NodeNLRI {
	return &base.NodeNLRI{ProtocolID: protocol, LocalNode: testLSNodeDescriptor()}
}

func testLSNodeNLRI80() []byte {
	descriptor := []byte{
		0x01, 0x00, 0x00, 0x10,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
	}
	payload := append([]byte{byte(base.Direct)}, make([]byte, 8)...)
	payload = append(payload, descriptor...)
	return append([]byte{0x00, 0x01, 0x00, byte(len(payload))}, payload...)
}

func testLSUpdate(tlvs ...lsSPFTLV) *bgp.Update {
	var attribute []byte
	for _, tlv := range tlvs {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header, tlv.typeID)
		binary.BigEndian.PutUint16(header[2:], uint16(len(tlv.value)))
		attribute = append(attribute, header...)
		attribute = append(attribute, tlv.value...)
	}
	return &bgp.Update{PathAttributes: []bgp.PathAttribute{{AttributeType: 29, Attribute: attribute}}}
}

func testLSSequence() lsSPFTLV {
	return lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
}

func TestValidateLSNLRI80(t *testing.T) {
	node := testLSNode(base.Direct)
	link := &base.LinkNLRI{ProtocolID: base.Direct, LocalNode: testLSNodeDescriptor(), RemoteNode: testLSNodeDescriptor()}
	prefix := &base.PrefixNLRI{LocalNode: testLSNodeDescriptor()}
	tests := []struct {
		name    string
		nlri    *ls.NLRI71
		update  *bgp.Update
		wantErr string
	}{
		{
			name:   "node with sequence number",
			nlri:   &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update: testLSUpdate(testLSSequence()),
		},
		{
			name:   "link with four octet IGP metric",
			nlri:   &ls.NLRI71{NLRI: []ls.Element{{Type: 2, LS: link}}},
			update: testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:   "prefix with four octet metric",
			nlri:   &ls.NLRI71{NLRI: []ls.Element{{Type: 3, LS: prefix}}},
			update: testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSPrefixMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:   "attribute discard preserves NLRI",
			nlri:   &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update: &bgp.Update{},
		},
		{
			name:    "missing sequence number",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(lsSPFTLV{typeID: 1024, value: []byte{0}}),
			wantErr: "sequence number",
		},
		{
			name:    "nil update",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			wantErr: "update is nil",
		},
		{
			name:    "nil NLRI",
			update:  testLSUpdate(testLSSequence()),
			wantErr: "NLRI is nil",
		},
		{
			name:    "malformed BGP-LS attribute",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(),
			wantErr: "invalid bgp-ls attribute",
		},
		{
			name:    "invalid sequence number length",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: make([]byte, 7)}),
			wantErr: "sequence number TLV has length 7",
		},
		{
			name: "missing BGP Router ID",
			nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: &base.NodeNLRI{
				ProtocolID: base.Direct,
				LocalNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
					512: {Type: 512, Length: 4, Value: []byte{0, 0, 0xfd, 0xe8}},
				}},
			}}}},
			update:  testLSUpdate(testLSSequence()),
			wantErr: "TLV 516",
		},
		{
			name:    "non-direct node protocol",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: testLSNode(base.OSPFv2)}}},
			update:  testLSUpdate(testLSSequence()),
			wantErr: "protocol ID",
		},
		{
			name:    "link metric is required",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 2, LS: link}}},
			update:  testLSUpdate(testLSSequence()),
			wantErr: "metric TLV",
		},
		{
			name:    "reserved status value",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{0}}),
			wantErr: "reserved value",
		},
		{
			name:   "unknown status value is preserved",
			nlri:   &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update: testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{254}}),
		},
		{
			name:    "all IGP metrics must be four octets",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 2, LS: link}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}, lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{10}}),
			wantErr: "metric TLV",
		},
		{
			name:    "invalid status length",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{1, 2}}),
			wantErr: "status TLV has length 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLSNLRI80(tt.nlri, tt.update)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateLSNLRI80() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateLSNLRI80() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestProcessNLRI80SubTypesRejectsInvalidInput(t *testing.T) {
	validUpdate := testLSUpdate(testLSSequence())
	tests := []struct {
		name   string
		nlri   bgp.MPNLRI
		update *bgp.Update
	}{
		{
			name:   "missing BGP-LS-SPF accessor",
			nlri:   lsSPFNoGetter{},
			update: validUpdate,
		},
		{
			name:   "decode failure",
			nlri:   lsSPFMockNLRI{err: errors.New("decode failure")},
			update: validUpdate,
		},
		{
			name:   "nil update",
			nlri:   lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: testLSNode(base.Direct)}}}},
			update: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processNLRI80SubTypes(tt.nlri, AddPrefix, minimalPeerHeader(), tt.update)
			if len(publisher.msgs) != 0 {
				t.Fatalf("processNLRI80SubTypes() published %d messages, want 0", len(publisher.msgs))
			}
		})
	}
}

func TestProcessNLRI80SubTypesTreatsMalformedAddAsWithdraw(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.processNLRI80SubTypes(
		lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: testLSNode(base.OSPFv2)}}}},
		AddPrefix,
		minimalPeerHeader(),
		testLSUpdate(testLSSequence()),
	)

	if len(publisher.msgs) != 1 {
		t.Fatalf("processNLRI80SubTypes() published %d messages, want 1", len(publisher.msgs))
	}
	var published LSNode
	if err := json.Unmarshal(publisher.msgs[0].payload, &published); err != nil {
		t.Fatalf("published LSNode JSON: %v", err)
	}
	if published.Action != "del" {
		t.Errorf("published Action = %q, want del", published.Action)
	}
}

func TestProcessMPUpdateLSNLRI80(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.processMPUpdate(&bgp.MPReachNLRI{
		AddressFamilyID:      16388,
		SubAddressFamilyID:   80,
		NextHopAddressLength: 4,
		NextHopAddress:       []byte{192, 0, 2, 2},
		NLRI:                 testLSNodeNLRI80(),
	}, AddPrefix, minimalPeerHeader(), testLSUpdate(testLSSequence()))

	if len(publisher.msgs) != 1 {
		t.Fatalf("processMPUpdate() published %d messages, want 1", len(publisher.msgs))
	}
	if publisher.msgs[0].msgType != bmp.LSNodeMsg {
		t.Fatalf("processMPUpdate() topic = %d, want LSNode topic %d", publisher.msgs[0].msgType, bmp.LSNodeMsg)
	}
	var published LSNode
	if err := json.Unmarshal(publisher.msgs[0].payload, &published); err != nil {
		t.Fatalf("published LSNode JSON: %v", err)
	}
	if published.Action != "add" || published.ProtocolID != base.Direct || published.ASN != 65000 {
		t.Errorf("published LSNode = action %q protocol %d ASN %d, want add/%d/65000", published.Action, published.ProtocolID, published.ASN, base.Direct)
	}
}
