package bmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func as4PeerUpOpen(value []byte) []byte {
	// Independent OPEN wire bytes: AS_TRANS, valid hold time/BGP ID, one
	// capability optional parameter. No serializer shares the decoder's logic.
	params := append([]byte{2, byte(2 + len(value)), 65, byte(len(value))}, value...)
	wire := bytes.Repeat([]byte{255}, 16)
	wire = binary.BigEndian.AppendUint16(wire, uint16(29+len(params)))
	wire = append(wire, 1, 4, 0x5b, 0xa0, 0, 90, 192, 0, 2, 1, byte(len(params)))
	return append(wire, params...)
}

func TestPeerUpAS4CapabilityWireValidation(t *testing.T) {
	valid := []byte{0xfa, 0x56, 0xea, 0} // 4200000000 exceeds the two-octet ASN range.
	for _, side := range []string{"sent", "received"} {
		for _, length := range []int{0, 1, 2, 3, 4, 5} {
			t.Run(fmt.Sprintf("%s/length_%d", side, length), func(t *testing.T) {
				value := bytes.Repeat([]byte{1}, length)
				if length == 4 {
					value = valid
				}
				sent, received := as4PeerUpOpen(valid), as4PeerUpOpen(valid)
				if side == "sent" {
					sent = as4PeerUpOpen(value)
				} else {
					received = as4PeerUpOpen(value)
				}
				wire := append(make([]byte, 20), sent...)
				wire = append(wire, received...)
				peerUp, err := UnmarshalPeerUpMessage(wire, false)
				if length != 4 {
					if err == nil || peerUp != nil {
						t.Fatalf("malformed %s OPEN accepted: %+v error=%v", side, peerUp, err)
					}
					if !strings.Contains(err.Error(), "code 65") {
						t.Fatalf("unrelated rejection: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				sentASN, sentOK := peerUp.SentOpen.Is4BytesASCapable()
				receivedASN, receivedOK := peerUp.ReceivedOpen.Is4BytesASCapable()
				if !sentOK || !receivedOK || sentASN != 4200000000 || receivedASN != 4200000000 {
					t.Fatalf("sent=(%d,%v), received=(%d,%v)", sentASN, sentOK, receivedASN, receivedOK)
				}
			})
		}
	}
}
