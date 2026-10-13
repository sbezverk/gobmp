package message

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
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

// testLSLinkWithAF returns a Direct link whose AF Link Descriptor TLV (1185)
// has the given length and first value octet.
func testLSLinkWithAF(length int, value byte) *base.LinkNLRI {
	v := make([]byte, length)
	v[0] = value
	return &base.LinkNLRI{
		ProtocolID: base.Direct,
		LocalNode:  testLSNodeDescriptor(),
		RemoteNode: testLSNodeDescriptor(),
		Link: &base.LinkDescriptor{LinkTLV: map[uint16]base.TLV{
			base.AFLinkDescriptorTLV: {Type: base.AFLinkDescriptorTLV, Length: uint16(length), Value: v},
		}},
	}
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

func testLSAttribute(tlvs ...lsSPFTLV) *bgpls.NLRI {
	attribute := &bgpls.NLRI{}
	for _, tlv := range tlvs {
		attribute.LS = append(attribute.LS, bgpls.TLV{Type: tlv.typeID, Length: uint16(len(tlv.value)), Value: tlv.value})
	}
	return attribute
}

func testLSSequence() lsSPFTLV {
	return lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
}

func testLSStatus() lsSPFTLV {
	return lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{1}}
}

// TestValidateLSNLRI80Element unit-tests the per-Element structural and
// metric checks in isolation, independent of the attribute-level sequence
// number/status gating covered by TestSplitLSNLRI80.
func TestValidateLSNLRI80Element(t *testing.T) {
	link := &base.LinkNLRI{ProtocolID: base.Direct, LocalNode: testLSNodeDescriptor(), RemoteNode: testLSNodeDescriptor()}
	prefix := &base.PrefixNLRI{ProtocolID: base.Direct, LocalNode: testLSNodeDescriptor()}

	tests := []struct {
		name      string
		element   ls.Element
		attribute *bgpls.NLRI
		wantErr   string
	}{
		{
			name:    "valid node",
			element: ls.Element{Type: 1, LS: testLSNode(base.Direct)},
		},
		{
			name:    "non-direct node protocol",
			element: ls.Element{Type: 1, LS: testLSNode(base.OSPFv2)},
			wantErr: "protocol ID",
		},
		{
			name:    "node type does not match NLRI type",
			element: ls.Element{Type: 1, LS: &base.LinkNLRI{}},
			wantErr: "node NLRI has unexpected type",
		},
		{
			name:    "node descriptor is required",
			element: ls.Element{Type: 1, LS: &base.NodeNLRI{ProtocolID: base.Direct}},
			wantErr: "missing node descriptor",
		},
		{
			// RFC 9815 Section 5.1.1: a missing mandatory TLV excludes the
			// NLRI from SPF; it is not malformed.
			name: "missing BGP Router ID is not malformed",
			element: ls.Element{Type: 1, LS: &base.NodeNLRI{
				ProtocolID: base.Direct,
				LocalNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
					512: {Type: 512, Length: 4, Value: []byte{0, 0, 0xfd, 0xe8}},
				}},
			}},
		},
		{
			name: "BGP Router ID with wrong length",
			element: ls.Element{Type: 1, LS: &base.NodeNLRI{
				ProtocolID: base.Direct,
				LocalNode: &base.NodeDescriptor{SubTLV: map[uint16]base.TLV{
					512: {Type: 512, Length: 4, Value: []byte{0, 0, 0xfd, 0xe8}},
					516: {Type: 516, Length: 3, Value: []byte{10, 0, 0}},
				}},
			}},
			wantErr: "TLV 516 has length 3, want 4",
		},
		{
			name:      "valid link",
			element:   ls.Element{Type: 2, LS: link},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:    "link type does not match NLRI type",
			element: ls.Element{Type: 2, LS: testLSNode(base.Direct)},
			wantErr: "link NLRI has unexpected type",
		},
		{
			name:    "non-direct link protocol",
			element: ls.Element{Type: 2, LS: &base.LinkNLRI{ProtocolID: base.OSPFv2}},
			wantErr: "link NLRI has protocol ID",
		},
		{
			name:    "link local descriptor is required",
			element: ls.Element{Type: 2, LS: &base.LinkNLRI{ProtocolID: base.Direct, RemoteNode: testLSNodeDescriptor()}},
			wantErr: "link local node descriptor",
		},
		{
			name:    "link remote descriptor is required",
			element: ls.Element{Type: 2, LS: &base.LinkNLRI{ProtocolID: base.Direct, LocalNode: testLSNodeDescriptor()}},
			wantErr: "link remote node descriptor",
		},
		{
			name:      "link metric is required",
			element:   ls.Element{Type: 2, LS: link},
			attribute: testLSAttribute(),
			wantErr:   "metric TLV",
		},
		{
			name:      "link metric must be four octets",
			element:   ls.Element{Type: 2, LS: link},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{10}}),
			wantErr:   "metric TLV",
		},
		{
			name:      "valid prefix",
			element:   ls.Element{Type: 3, LS: prefix},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSPrefixMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:    "prefix type does not match NLRI type",
			element: ls.Element{Type: 3, LS: testLSNode(base.Direct)},
			wantErr: "prefix NLRI has unexpected type",
		},
		{
			name:      "prefix protocol is the prefix origin, not Direct",
			element:   ls.Element{Type: 4, LS: &base.PrefixNLRI{ProtocolID: base.OSPFv2, LocalNode: testLSNodeDescriptor()}},
			attribute: testLSAttribute(),
		},
		{
			name:    "prefix local descriptor is required",
			element: ls.Element{Type: 3, LS: &base.PrefixNLRI{ProtocolID: base.ISISL2}},
			wantErr: "missing node descriptor",
		},
		{
			name:      "prefix metric is optional",
			element:   ls.Element{Type: 3, LS: prefix},
			attribute: testLSAttribute(),
		},
		{
			name:      "present prefix metric must be four octets",
			element:   ls.Element{Type: 3, LS: prefix},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSPrefixMetricTLV, value: []byte{10}}),
			wantErr:   "metric TLV 1155 has length 1",
		},
		{
			name:      "link with valid AF link descriptor",
			element:   ls.Element{Type: 2, LS: testLSLinkWithAF(1, 2)},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name: "link without AF link descriptor",
			element: ls.Element{Type: 2, LS: &base.LinkNLRI{
				ProtocolID: base.Direct,
				LocalNode:  testLSNodeDescriptor(),
				RemoteNode: testLSNodeDescriptor(),
				Link:       &base.LinkDescriptor{LinkTLV: map[uint16]base.TLV{}},
			}},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:      "link with undefined AF link descriptor value is ignored",
			element:   ls.Element{Type: 2, LS: testLSLinkWithAF(1, 3)},
			attribute: testLSAttribute(lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}),
		},
		{
			name:    "link with reserved AF link descriptor value 0",
			element: ls.Element{Type: 2, LS: testLSLinkWithAF(1, 0)},
			wantErr: "address family link descriptor TLV has reserved value 0",
		},
		{
			name:    "link with reserved AF link descriptor value 255",
			element: ls.Element{Type: 2, LS: testLSLinkWithAF(1, 255)},
			wantErr: "address family link descriptor TLV has reserved value 255",
		},
		{
			name:    "link with malformed AF link descriptor length",
			element: ls.Element{Type: 2, LS: testLSLinkWithAF(2, 1)},
			wantErr: "address family link descriptor TLV has length 2",
		},
		{
			// RFC 9552 Section 5.2: other NLRI types are preserved and
			// propagated, not validated against Node/Link/Prefix rules.
			name:    "SRv6 SID element type passes through",
			element: ls.Element{Type: 6, LS: nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLSNLRI80Element(tt.element, tt.attribute)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateLSNLRI80Element() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateLSNLRI80Element() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// TestSplitLSNLRI80 covers attribute-level validation (shared by every
// Element) and the per-Element valid/invalid split used to withdraw only
// the Elements that fail validation.
func TestSplitLSNLRI80(t *testing.T) {
	node := testLSNode(base.Direct)
	badNode := testLSNode(base.OSPFv2)

	tests := []struct {
		name        string
		nlri        *ls.NLRI71
		update      *bgp.Update
		wantErr     string
		wantValid   int
		wantInvalid int
	}{
		{
			name:      "node with sequence number and status",
			nlri:      &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:    testLSUpdate(testLSSequence(), testLSStatus()),
			wantValid: 1,
		},
		{
			name:        "attribute discard preserves NLRI",
			nlri:        &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:      &bgp.Update{},
			wantValid:   1,
			wantInvalid: 0,
		},
		{
			name:    "nil update",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			wantErr: "update is nil",
		},
		{
			name:    "nil NLRI",
			update:  testLSUpdate(testLSSequence(), testLSStatus()),
			wantErr: "NLRI is nil",
		},
		{
			name:    "malformed BGP-LS attribute",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(),
			wantErr: "invalid bgp-ls attribute",
		},
		{
			name:    "missing sequence number",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSStatus()),
			wantErr: "sequence number",
		},
		{
			name:    "invalid sequence number length",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(lsSPFTLV{typeID: bgpLSSPFSequenceNumberTLV, value: make([]byte, 7)}, testLSStatus()),
			wantErr: "sequence number TLV has length 7",
		},
		{
			name:      "status TLV is optional",
			nlri:      &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:    testLSUpdate(testLSSequence()),
			wantValid: 1,
		},
		{
			name:    "reserved status value 255",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{255}}),
			wantErr: "reserved value 255",
		},
		{
			name:    "reserved status value",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{0}}),
			wantErr: "reserved value",
		},
		{
			name:    "invalid status length",
			nlri:    &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: node}}},
			update:  testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{1, 2}}),
			wantErr: "status TLV has length 2",
		},
		{
			name: "one malformed element is withdrawn without discarding the valid one",
			nlri: &ls.NLRI71{NLRI: []ls.Element{
				{Type: 1, LS: node},
				{Type: 1, LS: badNode},
			}},
			update:      testLSUpdate(testLSSequence(), testLSStatus()),
			wantValid:   1,
			wantInvalid: 1,
		},
		{
			name: "SRv6 SID element type is preserved, not withdrawn",
			nlri: &ls.NLRI71{NLRI: []ls.Element{
				{Type: 1, LS: node},
				{Type: 6, LS: nil},
			}},
			update:      testLSUpdate(testLSSequence(), testLSStatus()),
			wantValid:   2,
			wantInvalid: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, invalid, err := splitLSNLRI80(tt.nlri, tt.update)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("splitLSNLRI80() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitLSNLRI80() unexpected error: %v", err)
			}
			if len(valid.NLRI) != tt.wantValid {
				t.Errorf("splitLSNLRI80() valid = %d elements, want %d", len(valid.NLRI), tt.wantValid)
			}
			if len(invalid.NLRI) != tt.wantInvalid {
				t.Errorf("splitLSNLRI80() invalid = %d elements, want %d", len(invalid.NLRI), tt.wantInvalid)
			}
		})
	}
}

func TestProcessNLRI80SubTypesRejectsInvalidInput(t *testing.T) {
	validUpdate := testLSUpdate(testLSSequence(), testLSStatus())
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
			name: "nil update does not panic",
			nlri: lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: testLSNode(base.Direct)}}}},
		},
	}

	for _, tt := range tests {
		for _, op := range []int{AddPrefix, DelPrefix} {
			t.Run(tt.name, func(t *testing.T) {
				publisher := &recordingPublisher{}
				p := &producer{publisher: publisher}
				p.processNLRI80SubTypes(tt.nlri, op, minimalPeerHeader(), tt.update)
				if len(publisher.msgs) != 0 {
					t.Fatalf("processNLRI80SubTypes() published %d messages, want 0", len(publisher.msgs))
				}
			})
		}
	}
}

func TestProcessNLRI80SubTypesTreatsMalformedAddAsWithdraw(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.processNLRI80SubTypes(
		lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{{Type: 1, LS: testLSNode(base.OSPFv2)}}}},
		AddPrefix,
		minimalPeerHeader(),
		testLSUpdate(testLSSequence(), testLSStatus()),
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

// TestProcessNLRI80SubTypesWithdrawPaths covers the RFC 9815 Section 7.1
// treat-as-withdraw paths and the plain withdrawal passthrough.
func TestProcessNLRI80SubTypesWithdrawPaths(t *testing.T) {
	linkMetric := lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}
	tests := []struct {
		name       string
		element    ls.Element
		operation  int
		update     *bgp.Update
		wantAction string
	}{
		{
			name:       "withdrawal is published as del",
			element:    ls.Element{Type: 1, LS: testLSNode(base.Direct)},
			operation:  DelPrefix,
			update:     testLSUpdate(),
			wantAction: "del",
		},
		{
			name:       "reserved status withdraws the NLRI",
			element:    ls.Element{Type: 1, LS: testLSNode(base.Direct)},
			operation:  AddPrefix,
			update:     testLSUpdate(testLSSequence(), lsSPFTLV{typeID: bgpLSSPFStatusTLV, value: []byte{255}}),
			wantAction: "del",
		},
		{
			name:       "reserved AF link descriptor withdraws the link",
			element:    ls.Element{Type: 2, LS: testLSLinkWithAF(1, 0)},
			operation:  AddPrefix,
			update:     testLSUpdate(testLSSequence(), linkMetric),
			wantAction: "del",
		},
		{
			name:       "link without status TLV is published",
			element:    ls.Element{Type: 2, LS: testLSLinkWithAF(1, 1)},
			operation:  AddPrefix,
			update:     testLSUpdate(testLSSequence(), linkMetric),
			wantAction: "add",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processNLRI80SubTypes(lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{tt.element}}}, tt.operation, minimalPeerHeader(), tt.update)
			if len(publisher.msgs) != 1 {
				t.Fatalf("processNLRI80SubTypes() published %d messages, want 1", len(publisher.msgs))
			}
			var published struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(publisher.msgs[0].payload, &published); err != nil {
				t.Fatalf("published JSON: %v", err)
			}
			if published.Action != tt.wantAction {
				t.Errorf("published Action = %q, want %q", published.Action, tt.wantAction)
			}
		})
	}
}

func TestProcessNLRI80SubTypesWithdrawsOnlyMalformedElement(t *testing.T) {
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.processNLRI80SubTypes(
		lsSPFMockNLRI{nlri: &ls.NLRI71{NLRI: []ls.Element{
			{Type: 1, LS: testLSNode(base.Direct)},
			{Type: 1, LS: testLSNode(base.OSPFv2)},
		}}},
		AddPrefix,
		minimalPeerHeader(),
		testLSUpdate(testLSSequence(), testLSStatus()),
	)

	if len(publisher.msgs) != 2 {
		t.Fatalf("processNLRI80SubTypes() published %d messages, want 2", len(publisher.msgs))
	}
	actions := map[string]int{}
	for _, msg := range publisher.msgs {
		var published LSNode
		if err := json.Unmarshal(msg.payload, &published); err != nil {
			t.Fatalf("published LSNode JSON: %v", err)
		}
		actions[published.Action]++
	}
	if actions["add"] != 1 || actions["del"] != 1 {
		t.Errorf("published actions = %v, want one add and one del", actions)
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
	}, AddPrefix, minimalPeerHeader(), testLSUpdate(testLSSequence(), testLSStatus()))

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

// testLSLinkNLRI80 returns a Direct Link NLRI whose link descriptors carry one
// Address Family Link Descriptor TLV (1185) per entry in afValues.
func testLSLinkNLRI80(afValues ...[]byte) []byte {
	nodeDescriptor := func(typeID byte) []byte {
		return []byte{
			0x01, typeID, 0x00, 0x10,
			0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
			0x02, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
		}
	}
	payload := append([]byte{byte(base.Direct)}, make([]byte, 8)...)
	payload = append(payload, nodeDescriptor(0x00)...)
	payload = append(payload, nodeDescriptor(0x01)...)
	for _, af := range afValues {
		payload = append(payload, 0x04, 0xa1, 0x00, byte(len(af)))
		payload = append(payload, af...)
	}
	return append([]byte{0x00, 0x02, 0x00, byte(len(payload))}, payload...)
}

// TestProcessMPUpdateLSNLRI80RepeatedAFLinkTLV decodes AFI 16388 MP_REACH_NLRI
// and MP_UNREACH_NLRI attributes from wire bytes. Per RFC 9815 Section 5.2.2.1
// an unnumbered link may carry "separate Address Family Link Descriptor TLVs
// for IPv4 and IPv6"; the Link NLRI must be published, an undefined value
// (3-254) is ignored, and a reserved value or wrong length in any instance
// makes it malformed (treat-as-withdraw, Section 7.1). SAFI 71 shares the
// link descriptor parser, so it must accept the repeated TLV too.
func TestProcessMPUpdateLSNLRI80RepeatedAFLinkTLV(t *testing.T) {
	tests := []struct {
		name       string
		safi       byte
		withdraw   bool
		afValues   [][]byte
		wantAction string
	}{
		{name: "IPv4 and IPv6 AF link descriptors", safi: 80, afValues: [][]byte{{1}, {2}}, wantAction: "add"},
		{name: "same value repeated", safi: 80, afValues: [][]byte{{1}, {1}}, wantAction: "add"},
		{name: "undefined value in second instance", safi: 80, afValues: [][]byte{{1}, {7}}, wantAction: "add"},
		{name: "reserved value in second instance", safi: 80, afValues: [][]byte{{1}, {255}}, wantAction: "del"},
		{name: "wrong length in second instance", safi: 80, afValues: [][]byte{{1}, {2, 0}}, wantAction: "del"},
		{name: "withdraw with IPv4 and IPv6 AF link descriptors", safi: 80, withdraw: true, afValues: [][]byte{{1}, {2}}, wantAction: "del"},
		{name: "SAFI 71 with IPv4 and IPv6 AF link descriptors", safi: 71, afValues: [][]byte{{1}, {2}}, wantAction: "add"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nlri bgp.MPNLRI
			var err error
			operation := AddPrefix
			if tt.withdraw {
				unreach := append([]byte{0x40, 0x04, tt.safi}, testLSLinkNLRI80(tt.afValues...)...)
				nlri, err = bgp.UnmarshalMPUnReachNLRI(unreach, map[int]bool{})
				operation = DelPrefix
			} else {
				reach := []byte{0x40, 0x04, tt.safi, 0x04, 0xc0, 0x00, 0x02, 0x02, 0x00}
				reach = append(reach, testLSLinkNLRI80(tt.afValues...)...)
				nlri, err = bgp.UnmarshalMPReachNLRI(reach, false, map[int]bool{})
			}
			if err != nil {
				t.Fatalf("unmarshal MP NLRI error = %v", err)
			}

			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			metric := lsSPFTLV{typeID: bgpLSIGPMetricTLV, value: []byte{0, 0, 0, 10}}
			p.processMPUpdate(nlri, operation, minimalPeerHeader(), testLSUpdate(testLSSequence(), metric))

			if len(publisher.msgs) != 1 {
				t.Fatalf("processMPUpdate() published %d messages, want 1", len(publisher.msgs))
			}
			if publisher.msgs[0].msgType != bmp.LSLinkMsg {
				t.Fatalf("processMPUpdate() topic = %d, want LSLink topic %d", publisher.msgs[0].msgType, bmp.LSLinkMsg)
			}
			var got LSLink
			if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
				t.Fatalf("published LSLink JSON: %v", err)
			}
			if got.Action != tt.wantAction {
				t.Errorf("published LSLink action = %q, want %q", got.Action, tt.wantAction)
			}
		})
	}
}

func TestProcessMPUpdateLSNLRI71(t *testing.T) {
	tests := []struct {
		name         string
		reach        []byte
		wantAction   string
		wantProtocol base.ProtoID
		wantASN      uint32
	}{
		{
			name: "direct node",
			// RFC 9552 Section 5.2: BGP-LS Node NLRI in an AFI 16388/SAFI 71 MP_REACH_NLRI.
			reach: []byte{
				0x40, 0x04, 0x47, 0x04, 0xc0, 0x00, 0x02, 0x02, 0x00,
				0x00, 0x01, 0x00, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x02,
				0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x04,
				0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
			},
			wantAction:   "add",
			wantProtocol: base.Direct,
			wantASN:      65000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri, err := bgp.UnmarshalMPReachNLRI(tt.reach, false, map[int]bool{})
			if err != nil {
				t.Fatalf("UnmarshalMPReachNLRI() error = %v", err)
			}

			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.processMPUpdate(nlri, AddPrefix, minimalPeerHeader(), minimalUpdate())

			if len(publisher.msgs) != 1 {
				t.Fatalf("processMPUpdate() published %d messages, want 1", len(publisher.msgs))
			}
			if publisher.msgs[0].msgType != bmp.LSNodeMsg {
				t.Fatalf("processMPUpdate() topic = %d, want LSNode topic %d", publisher.msgs[0].msgType, bmp.LSNodeMsg)
			}

			var got LSNode
			if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
				t.Fatalf("published LSNode JSON: %v", err)
			}
			if got.Action != tt.wantAction || got.ProtocolID != tt.wantProtocol || got.ASN != tt.wantASN {
				t.Errorf("published LSNode = action %q protocol %d ASN %d, want %q/%d/%d", got.Action, got.ProtocolID, got.ASN, tt.wantAction, tt.wantProtocol, tt.wantASN)
			}
		})
	}
}
