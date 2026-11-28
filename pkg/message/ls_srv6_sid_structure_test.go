package message

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// publishedSIDStructure holds the published SID Structure lengths (RFC 9514 §8).
type publishedSIDStructure struct {
	LocatorBlock uint8 `json:"locator_block_length"`
	LocatorNode  uint8 `json:"locator_node_length"`
	Function     uint8 `json:"function_length"`
	Argument     uint8 `json:"argument_length"`
}

// publishedEndXSID holds the published End.X SID and its SID Structure.
type publishedEndXSID struct {
	SID     string                  `json:"sid"`
	SubTLVs []publishedSIDStructure `json:"sub_tlvs"`
}

// RFC 9552 §5.2: IS-IS L2 NLRI header and the local Node Descriptors.
var (
	sidStructureNLRIHeader = []byte{2, 0, 0, 0, 0, 0, 0, 0, 7}
	sidStructureLocalNode  = messageInterASTLV(256, messageInterASTLV(515, []byte{0, 1, 2, 3, 4, 5}))
)

// publishLSRoute sends one BGP-LS NLRI and its attribute 29 through the producer,
// in MP_UNREACH_NLRI for a withdrawal and in MP_REACH_NLRI otherwise. It checks
// the message type and action, and returns the published fields.
func publishLSRoute(t *testing.T, nlri, attribute []byte, isWithdraw bool, wantType int) map[string]json.RawMessage {
	t.Helper()
	mpType, mpValue, wantAction := byte(14), []byte{0x40, 4, 71, 4, 192, 0, 2, 1, 0}, `"add"`
	if isWithdraw {
		mpType, mpValue, wantAction = 15, []byte{0x40, 4, 71}, `"del"`
	}
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8} // ORIGIN and AS_PATH
	attrs = append(attrs, lsPathAttribute(mpType, append(mpValue, nlri...))...)
	attrs = append(attrs, lsPathAttribute(29, attribute)...)
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}

	p.produceRouteMessage(bmp.Message{PeerHeader: minimalPeerHeader(), Payload: eorWire(t, nil, attrs, nil)})

	if len(publisher.msgs) != 1 || publisher.msgs[0].msgType != wantType {
		t.Fatalf("published %v, want one message of type %d", publisher.msgs, wantType)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(publisher.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published message: %v", err)
	}
	if string(got["action"]) != wantAction {
		t.Errorf("action = %s, want %s", got["action"], wantAction)
	}
	return got
}

func TestPublishSRv6SIDStructureLength(t *testing.T) {
	sid := []byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12}
	nlri := messageInterASTLV(6, bytes.Join([][]byte{sidStructureNLRIHeader, sidStructureLocalNode, messageInterASTLV(518, sid)}, nil))
	decoded := &publishedSIDStructure{LocatorBlock: 40, LocatorNode: 24, Function: 16, Argument: 8}

	tests := []struct {
		name       string
		value      []byte
		isWithdraw bool
		want       *publishedSIDStructure // nil means srv6_sid_structure is absent
	}{
		{name: "omits srv6_sid_structure from an add when the value is empty", value: []byte{}},
		{name: "omits srv6_sid_structure from an add when the value has three octets", value: []byte{40, 24, 16}},
		{name: "omits srv6_sid_structure from an add when the value has five octets", value: []byte{40, 24, 16, 8, 0}},
		{name: "publishes the decoded srv6_sid_structure in an add when the value has four octets", value: []byte{40, 24, 16, 8}, want: decoded},
		{name: "omits srv6_sid_structure from a del when the value has three octets", value: []byte{40, 24, 16}, isWithdraw: true},
		{name: "publishes the decoded srv6_sid_structure in a del when the value has four octets", value: []byte{40, 24, 16, 8}, isWithdraw: true, want: decoded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			published := publishLSRoute(t, nlri, messageInterASTLV(1252, tc.value), tc.isWithdraw, bmp.LSSRv6SIDMsg)

			raw, present := published["srv6_sid_structure"]
			if tc.want == nil {
				if present {
					t.Errorf("srv6_sid_structure = %s, want it absent", raw)
				}
				return
			}
			var got publishedSIDStructure
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal srv6_sid_structure %q: %v", raw, err)
			}
			if got != *tc.want {
				t.Errorf("srv6_sid_structure = %+v, want %+v", got, *tc.want)
			}
		})
	}
}

func TestPublishLinkEndXSIDStructureLength(t *testing.T) {
	remoteNode := messageInterASTLV(257, messageInterASTLV(515, []byte{0, 1, 2, 3, 4, 6}))
	nlri := messageInterASTLV(2, bytes.Join([][]byte{sidStructureNLRIHeader, sidStructureLocalNode, remoteNode}, nil))
	// RFC 9514 §4.1: one End.X SID TLV per SID; the last octet tells the SIDs apart.
	endXSID := func(lastOctet byte, structure ...byte) []byte {
		value := []byte{0, 5, 0, 0, 0, 0, 0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, lastOctet}
		return messageInterASTLV(1106, append(value, messageInterASTLV(1252, structure)...))
	}
	invalidThenValid := append(endXSID(0x11, 40, 24, 16, 8, 0), endXSID(0x12, 40, 24, 16, 8)...)
	decoded := []publishedSIDStructure{{LocatorBlock: 40, LocatorNode: 24, Function: 16, Argument: 8}}
	first := []publishedEndXSID{{SID: "2001:db8:1::11", SubTLVs: decoded}}
	second := []publishedEndXSID{{SID: "2001:db8:1::12", SubTLVs: decoded}}

	tests := []struct {
		name       string
		attribute  []byte
		isWithdraw bool
		want       []publishedEndXSID // nil means srv6_endx_sid is absent
	}{
		{name: "omits srv6_endx_sid from an add when the SID Structure is empty", attribute: endXSID(0x11)},
		{name: "omits srv6_endx_sid from an add when the SID Structure has three octets", attribute: endXSID(0x11, 40, 24, 16)},
		{name: "omits srv6_endx_sid from an add when the SID Structure has five octets", attribute: endXSID(0x11, 40, 24, 16, 8, 0)},
		{name: "publishes the decoded srv6_endx_sid in an add when the SID Structure has four octets", attribute: endXSID(0x11, 40, 24, 16, 8), want: first},
		{name: "publishes only the valid End.X SID in an add when an earlier one has a five octet SID Structure", attribute: invalidThenValid, want: second},
		{name: "omits srv6_endx_sid from a del when the SID Structure has three octets", attribute: endXSID(0x11, 40, 24, 16), isWithdraw: true},
		{name: "publishes the decoded srv6_endx_sid in a del when the SID Structure has four octets", attribute: endXSID(0x11, 40, 24, 16, 8), isWithdraw: true, want: first},
		{name: "publishes only the valid End.X SID in a del when an earlier one has a five octet SID Structure", attribute: invalidThenValid, isWithdraw: true, want: second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			published := publishLSRoute(t, nlri, tc.attribute, tc.isWithdraw, bmp.LSLinkMsg)

			raw, present := published["srv6_endx_sid"]
			if tc.want == nil {
				if present {
					t.Errorf("srv6_endx_sid = %s, want it absent", raw)
				}
				return
			}
			var got []publishedEndXSID
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatalf("unmarshal srv6_endx_sid %q: %v", raw, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("srv6_endx_sid = %+v, want %+v", got, tc.want)
			}
		})
	}
}
