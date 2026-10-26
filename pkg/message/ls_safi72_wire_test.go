package message

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// testLSVPNEntry encodes one VPN NLRI per RFC 9552 §5.2 Figure 6.
func testLSVPNEntry(typ uint16, rd, body []byte) []byte {
	wire := make([]byte, 4, 4+len(rd)+len(body))
	binary.BigEndian.PutUint16(wire, typ)
	binary.BigEndian.PutUint16(wire[2:], uint16(len(rd)+len(body)))
	wire = append(wire, rd...)
	return append(wire, body...)
}

func TestProcessMPUpdateSAFI72Wire(t *testing.T) {
	rds := []struct {
		wire []byte
		want string
	}{
		{[]byte{0, 0, 0, 100, 0, 0, 0, 1}, "100:1"},
		{[]byte{0, 1, 192, 0, 2, 1, 0, 100}, "192.0.2.1:100"},
		{[]byte{0, 2, 0, 1, 0, 0, 0, 100}, "65536:100"},
	}
	for i, nodeRD := range rds {
		opaqueRD := rds[(i+1)%len(rds)]
		for _, withdraw := range []bool{false, true} {
			for _, addPath := range []bool{false, true} {
				t.Run(fmt.Sprintf("RD%d withdraw=%t AddPath=%t", i, withdraw, addPath), func(t *testing.T) {
					node := testLSVPNEntry(1, nodeRD.wire, testLSNodeNLRI80()[4:])
					// SAFI 72 type 7 stays opaque; its payload is never decoded.
					opaque := testLSVPNEntry(7, opaqueRD.wire, []byte{0xde, 0xad, 0xbe})
					if addPath {
						node = append([]byte{0, 0, 0, 7}, node...)
						opaque = append([]byte{0, 0, 0, 9}, opaque...)
					}
					payload := append(node, opaque...)
					var nlri bgp.MPNLRI
					var err error
					operation, action := AddPrefix, "add"
					if withdraw {
						nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0x40, 0x04, 72}, payload...), map[int]bool{72: addPath})
						operation, action = DelPrefix, "del"
					} else {
						nlri, err = bgp.UnmarshalMPReachNLRI(append([]byte{0x40, 0x04, 72, 4, 192, 0, 2, 2, 0}, payload...), false, map[int]bool{72: addPath})
					}
					if err != nil {
						t.Fatal(err)
					}
					decoded, err := nlri.GetNLRI72()
					if err != nil || len(decoded.NLRI) != 2 {
						t.Fatalf("GetNLRI72 = %+v, %v; want two elements", decoded, err)
					}
					wantPathIDs := []uint32{0, 0}
					if addPath {
						wantPathIDs = []uint32{7, 9}
					}
					for j, want := range wantPathIDs {
						if decoded.NLRI[j].PathID != want {
							t.Errorf("element %d PathID = %d, want %d", j, decoded.NLRI[j].PathID, want)
						}
					}
					rec := &recordingPublisher{}
					p := &producer{publisher: rec}
					p.processMPUpdate(nlri, operation, minimalPeerHeader(), minimalUpdate())
					if len(rec.msgs) != 2 || rec.msgs[0].msgType != bmp.LSNodeMsg || rec.msgs[1].msgType != bmp.LSOpaqueMsg {
						t.Fatalf("published = %+v, want Node followed by opaque", rec.msgs)
					}
					var gotNode LSNode
					if err := json.Unmarshal(rec.msgs[0].payload, &gotNode); err != nil {
						t.Fatal(err)
					}
					if gotNode.RD != nodeRD.want || gotNode.Action != action || gotNode.ASN != 65000 || gotNode.ProtocolID != 4 {
						t.Errorf("Node = %+v, want RD %s action %s ASN 65000 Direct protocol", gotNode, nodeRD.want, action)
					}
					var gotOpaque LSOpaque
					if err := json.Unmarshal(rec.msgs[1].payload, &gotOpaque); err != nil {
						t.Fatal(err)
					}
					if gotOpaque.RD != opaqueRD.want || gotOpaque.Action != action || gotOpaque.SAFI != 72 || gotOpaque.NLRIType != 7 || gotOpaque.NLRI != "deadbe" {
						t.Errorf("opaque = %+v, want RD %s action %s SAFI 72 type 7 payload deadbe", gotOpaque, opaqueRD.want, action)
					}
				})
			}
		}
	}
}

func TestProcessMPUpdateSAFI72MalformedWire(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(fmt.Sprintf("withdraw=%t", withdraw), func(t *testing.T) {
			// A malformed tail invalidates the NLRI batch before any publication.
			payload := testLSVPNEntry(1, testRD, testLSNodeNLRI80()[4:])
			payload = append(payload, 0)
			var nlri bgp.MPNLRI
			var err error
			operation := AddPrefix
			if withdraw {
				nlri, err = bgp.UnmarshalMPUnReachNLRI(append([]byte{0x40, 0x04, 72}, payload...), nil)
				operation = DelPrefix
			} else {
				nlri, err = bgp.UnmarshalMPReachNLRI(append([]byte{0x40, 0x04, 72, 4, 192, 0, 2, 2, 0}, payload...), false, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			rec := &recordingPublisher{}
			p := &producer{publisher: rec}
			p.processMPUpdate(nlri, operation, minimalPeerHeader(), minimalUpdate())
			if len(rec.msgs) != 0 {
				t.Errorf("published %d messages for malformed NLRI, want none", len(rec.msgs))
			}
		})
	}
}
