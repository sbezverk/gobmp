package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// RFC 4271 Section 4.3 permits arbitrary trailing bits in the last NLRI octet.
// Publication must use the network prefix, while leaving the wire data intact.
func TestPrefixPaddingPublication(t *testing.T) {
	prefixes := []struct {
		bits   byte
		wire   []byte
		v4, v6 string
	}{
		{0, nil, "0.0.0.0", "::"},
		{8, []byte{10}, "10.0.0.0", "a00::"},
		{17, []byte{10, 1, 0}, "10.1.0.0", "a01::"},
		{17, []byte{10, 1, 0x80}, "10.1.128.0", "a01:8000::"},
		{32, []byte{10, 1, 2, 3}, "10.1.2.3", "a01:203::"},
		{65, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0x80}, "", "2001:db8:0:0:8000::"},
		{127, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, "", "2001:db8::2"},
		{128, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}, "", "2001:db8::3"},
	}
	families := []struct {
		name   string
		afi    uint16
		safi   byte
		legacy bool
	}{
		{"legacy", 1, 1, true}, {"mp4", 1, 1, false}, {"mp6", 2, 1, false},
		{"lu4", 1, 4, false}, {"lu6", 2, 4, false},
	}
	for _, family := range families {
		for _, prefix := range prefixes {
			if family.afi == 1 && prefix.bits > 32 {
				continue
			}
			for _, split := range []bool{false, true} {
				for _, addPath := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d/split=%v/addpath=%v", family.name, prefix.bits, split, addPath), func(t *testing.T) {
						recorder := &recordingPublisher{}
						p := NewProducer(recorder, split).(*producer)
						ph := makePeerHeader(t, bmp.PeerType0, 0)
						if addPath {
							familyKey := bgp.AFISAFI{AFI: family.afi, SAFI: family.safi}
							addPathPeerUp(t, p, ph, addPathOpen(t, nil, map[bgp.AFISAFI]uint8{familyKey: 1}), addPathOpen(t, nil, map[bgp.AFISAFI]uint8{familyKey: 2}))
						}
						publish := func(padded, withdraw bool, pathID uint32) UnicastPrefix {
							t.Helper()
							octets := append([]byte(nil), prefix.wire...)
							if padded && prefix.bits%8 != 0 {
								octets[len(octets)-1] |= byte((1 << (8 - prefix.bits%8)) - 1)
							}
							nlri := []byte{prefix.bits}
							if family.safi == 4 {
								// Two labels: semantic prefix length excludes both label entries.
								nlri = []byte{prefix.bits + 48, 0, 1, 0, 0, 2, 1}
								if withdraw {
									nlri = []byte{prefix.bits + 24, 0x80, 0, 0}
								}
							}
							nlri = append(nlri, octets...)
							if addPath {
								nlri = append(binary.BigEndian.AppendUint32(nil, pathID), nlri...)
							}
							attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 4, 192, 0, 2, 1}
							var legacy, withdrawn []byte
							if family.legacy {
								if withdraw {
									withdrawn = nlri
								} else {
									legacy = nlri
								}
							} else if withdraw {
								attrs = append(attrs, dPathUnreach(family.afi, family.safi, nlri)...)
							} else {
								nh := []byte{192, 0, 2, 1}
								if family.afi == 2 {
									nh = []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
								}
								attrs = append(attrs, dPathReach(family.afi, family.safi, nh, nlri)...)
							}
							body := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
							body = append(body, withdrawn...)
							body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
							body = append(body, attrs...)
							body = append(body, legacy...)
							wire := bytes.Repeat([]byte{255}, 16)
							wire = binary.BigEndian.AppendUint16(wire, uint16(19+len(body)))
							wire = append(wire, 2)
							wire = append(wire, body...)
							original := bytes.Clone(wire)
							rm, err := bmp.UnmarshalBMPRouteMonitorMessage(wire)
							if err != nil {
								t.Fatal(err)
							}
							before, err := json.Marshal(rm.Update)
							if err != nil {
								t.Fatal(err)
							}
							recorder.msgs = nil
							p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: rm})
							after, err := json.Marshal(rm.Update)
							if err != nil {
								t.Fatal(err)
							}
							if !bytes.Equal(wire, original) || !bytes.Equal(before, after) {
								t.Fatal("parser/publication changed input or UPDATE")
							}
							if len(recorder.msgs) != 1 {
								t.Fatalf("got %d publications, want one", len(recorder.msgs))
							}
							var got UnicastPrefix
							if err := json.Unmarshal(recorder.msgs[0].payload, &got); err != nil {
								t.Fatal(err)
							}
							want := prefix.v4
							if family.afi == 2 {
								want = prefix.v6
							}
							if got.Prefix != want || got.PrefixLen != int32(prefix.bits) {
								t.Fatalf("prefix = %s/%d, want %s/%d", got.Prefix, got.PrefixLen, want, prefix.bits)
							}
							action := "add"
							if withdraw {
								action = "del"
							}
							if got.Action != action || got.Hash == "" {
								t.Fatalf("action/hash = %q/%q", got.Action, got.Hash)
							}
							if addPath && got.PathID != int32(pathID) {
								t.Fatalf("PathID = %d, want %d", got.PathID, pathID)
							}
							return got
						}
						canonical := publish(false, false, 1)
						padded := publish(true, false, 1)
						withdrawn := publish(true, true, 1)
						if canonical.Hash != padded.Hash {
							t.Fatal("padding changed announcement identity")
						}
						// LU label-independent withdrawal identity is a separate fix. Its wire
						// withdrawal still must publish the same canonical prefix here.
						if family.safi != 4 && canonical.Hash != withdrawn.Hash {
							t.Fatal("padding changed withdrawal identity")
						}
						if addPath && publish(true, false, 2).Hash == canonical.Hash {
							t.Fatal("different PathIDs share identity")
						}
					})
				}
			}
		}
	}
}
