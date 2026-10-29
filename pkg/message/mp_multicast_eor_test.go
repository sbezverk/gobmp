package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// mpUpdateWire builds an UPDATE body: pre (conforming attributes) followed by
// one optional MP_* path attribute.
func mpUpdateWire(pre []byte, attrType byte, value []byte) []byte {
	attrs := append([]byte{}, pre...)
	attrs = append(attrs, 0x80, attrType, byte(len(value)))
	attrs = append(attrs, value...)
	return append([]byte{0x00, 0x00, 0x00, byte(len(attrs))}, attrs...)
}

// reachPre is ORIGIN (IGP) and an empty AS_PATH; RFC 4760 §3 requires both
// in an UPDATE carrying MP_REACH_NLRI.
var reachPre = []byte{0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00}

// TestMulticast_EoRFromWire feeds raw UPDATE bytes through the route monitor
// path. RFC 4724 §2: End-of-RIB is an UPDATE that "contains only the
// MP_UNREACH_NLRI attribute" with no withdrawn routes; an empty MP_REACH is not.
func TestMulticast_EoRFromWire(t *testing.T) {
	const tableName = "VRF-MC"
	tests := []struct {
		name          string
		pre           []byte
		attrType      byte
		value         []byte
		peerType      bmp.PeerType
		flags         byte
		wantMsgs      int
		wantType      int
		wantIPv4      bool
		wantPost      bool
		wantLocRIB    bool
		wantTableName string
	}{
		{
			name:     "AFI1 empty unreach is EoR",
			attrType: bgp.MP_UNREACH_NLRI,
			value:    []byte{0x00, 0x01, 0x02},
			wantMsgs: 1,
			wantType: bmp.MulticastV4Msg,
			wantIPv4: true,
		},
		{
			name:     "AFI2 empty unreach is EoR",
			attrType: bgp.MP_UNREACH_NLRI,
			value:    []byte{0x00, 0x02, 0x02},
			wantMsgs: 1,
			wantType: bmp.MulticastV6Msg,
		},
		{
			name:     "AFI1 empty unreach post-policy (L=1)",
			attrType: bgp.MP_UNREACH_NLRI,
			value:    []byte{0x00, 0x01, 0x02},
			flags:    0x40,
			wantMsgs: 1,
			wantType: bmp.MulticastV4Msg,
			wantIPv4: true,
			wantPost: true,
		},
		{
			name:          "AFI1 empty unreach Loc-RIB",
			attrType:      bgp.MP_UNREACH_NLRI,
			value:         []byte{0x00, 0x01, 0x02},
			peerType:      bmp.PeerType3,
			wantMsgs:      1,
			wantType:      bmp.MulticastV4Msg,
			wantIPv4:      true,
			wantLocRIB:    true,
			wantTableName: tableName,
		},
		{
			name:     "AFI1 empty reach is not EoR",
			pre:      reachPre,
			attrType: bgp.MP_REACH_NLRI,
			value:    []byte{0x00, 0x01, 0x02, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x00},
		},
		{
			name:     "AFI2 empty reach is not EoR",
			pre:      reachPre,
			attrType: bgp.MP_REACH_NLRI,
			value:    []byte{0x00, 0x02, 0x02, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{}
			p := NewProducer(pub, false).(*producer)
			ph := makePeerHeader(t, tt.peerType, tt.flags)
			if tt.wantLocRIB {
				key := ph.GetPeerBGPIDString() + ph.GetPeerDistinguisherString()
				p.tableLock.Lock()
				p.tableProperties[key] = PerTableProperties{
					addPathCapable: make(map[int]bool),
					tableInfoTLVs:  []bmp.InformationalTLV{{InformationType: 3, Information: []byte(tableName)}},
				}
				p.tableLock.Unlock()
			}
			update, err := bgp.UnmarshalBGPUpdate(mpUpdateWire(tt.pre, tt.attrType, tt.value))
			if err != nil {
				t.Fatalf("UnmarshalBGPUpdate: %v", err)
			}
			p.produceRouteMonitorMessage(bmp.Message{
				PeerHeader: ph,
				Payload:    &bmp.RouteMonitor{Update: update},
			})
			if len(pub.msgs) != tt.wantMsgs {
				t.Fatalf("published %d messages, want %d", len(pub.msgs), tt.wantMsgs)
			}
			if tt.wantMsgs == 0 {
				return
			}
			if pub.msgs[0].msgType != tt.wantType {
				t.Errorf("msgType = %d, want %d", pub.msgs[0].msgType, tt.wantType)
			}
			var got MulticastPrefix
			if err := json.Unmarshal(pub.msgs[0].payload, &got); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if !got.IsEOR || got.Action != "del" {
				t.Errorf("is_eor=%v action=%q, want true/del", got.IsEOR, got.Action)
			}
			if got.IsIPv4 != tt.wantIPv4 {
				t.Errorf("is_ipv4 = %v, want %v", got.IsIPv4, tt.wantIPv4)
			}
			if got.PeerIP != ph.GetPeerAddrString() {
				t.Errorf("peer_ip = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
			}
			if got.IsAdjRIBInPost != tt.wantPost {
				t.Errorf("is_adj_rib_in_post_policy = %v, want %v", got.IsAdjRIBInPost, tt.wantPost)
			}
			if got.IsLocRIB != tt.wantLocRIB || got.TableName != tt.wantTableName {
				t.Errorf("is_loc_rib=%v table_name=%q, want %v/%q", got.IsLocRIB, got.TableName, tt.wantLocRIB, tt.wantTableName)
			}
		})
	}
}
