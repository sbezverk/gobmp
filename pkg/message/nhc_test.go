package message

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func parsedNHC(t *testing.T, value []byte) *bgp.NHC {
	t.Helper()
	nhc, err := bgp.UnmarshalNHC(value)
	if err != nil {
		t.Fatalf("UnmarshalNHC: %v", err)
	}
	return nhc
}

func TestValidateNHC(t *testing.T) {
	tlv := []byte{0, 4, 0, 0}
	t.Run("matching next hop retained", func(t *testing.T) {
		value := append([]byte{0, 1, 1, 4, 198, 51, 100, 1}, tlv...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 1, 1, []byte{198, 51, 100, 1}, nil)
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded {
			t.Fatal("matching NHC was discarded")
		}
	})
	t.Run("mismatching next hop discarded", func(t *testing.T) {
		value := append([]byte{0, 1, 1, 4, 198, 51, 100, 1}, tlv...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 1, 1, []byte{198, 51, 100, 2}, nil)
		if update.BaseAttributes.NHC != nil || !update.BaseAttributes.NHCDiscarded {
			t.Fatal("mismatching NHC was not discarded")
		}
	})
	t.Run("link-local uses inbound peer identity", func(t *testing.T) {
		nextHop := net.ParseIP("fe80::1").To16()
		value := append([]byte{0, 2, 1, 16}, nextHop...)
		value = append(value, []byte{0, 3, 0, 8, 192, 0, 2, 1, 0, 0, 253, 232}...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		ph := &bmp.PerPeerHeader{PeerAS: 65000, PeerBGPID: []byte{192, 0, 2, 1}}
		validateNHC(update, 2, 1, nextHop, ph)
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded || update.BaseAttributes.NHCUnverified {
			t.Fatal("link-local NHC with matching inbound peer identity was not verified")
		}
	})
	t.Run("link-local outbound identity unavailable", func(t *testing.T) {
		nextHop := net.ParseIP("fe80::1").To16()
		value := append([]byte{0, 2, 1, 16}, nextHop...)
		value = append(value, []byte{0, 3, 0, 8, 192, 0, 2, 1, 0, 0, 253, 232}...)
		update := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{NHC: parsedNHC(t, value)}}
		validateNHC(update, 2, 1, nextHop, makePeerHeader(t, bmp.PeerType0, 0x10))
		if update.BaseAttributes.NHC == nil || update.BaseAttributes.NHCDiscarded || !update.BaseAttributes.NHCUnverified {
			t.Fatal("unverifiable outbound link-local NHC was not retained and marked")
		}
	})
}

func TestCopyUpdateCopiesNHCState(t *testing.T) {
	original := &bgp.Update{BaseAttributes: &bgp.BaseAttributes{
		NHCAttr: []byte{1},
		NHC: &bgp.NHC{
			NextHop: []byte{192, 0, 2, 1},
			Characteristics: []bgp.NHCCharacteristic{{
				Code:  4,
				Value: []byte{1},
			}},
			BGPID: &bgp.NHCBGPID{Identifier: "192.0.2.1", AS: 65000},
		},
	}}
	copied := copyUpdate(original)
	copied.BaseAttributes.NHCAttr[0] = 2
	copied.BaseAttributes.NHC.NextHop[0] = 198
	copied.BaseAttributes.NHC.Characteristics[0].Value[0] = 2
	copied.BaseAttributes.NHC.BGPID.AS = 65001
	if original.BaseAttributes.NHCAttr[0] != 1 || original.BaseAttributes.NHC.NextHop[0] != 192 || original.BaseAttributes.NHC.Characteristics[0].Value[0] != 1 || original.BaseAttributes.NHC.BGPID.AS != 65000 {
		t.Fatal("copyUpdate shared mutable NHC state with the original update")
	}
}

func TestRouteMonitorPublishesMPReachAndUnreach(t *testing.T) {
	publisher := &recordingPublisher{}
	p := NewProducer(publisher, false).(*producer)
	nhcValue := []byte{0, 1, 1, 4, 10, 0, 0, 1, 0, 4, 0, 0}
	nhc, err := bgp.UnmarshalNHC(nhcValue)
	if err != nil {
		t.Fatalf("UnmarshalNHC: %v", err)
	}
	update := &bgp.Update{
		PathAttributes: []bgp.PathAttribute{
			{AttributeType: bgp.MP_UNREACH_NLRI, Attribute: []byte{0, 1, 1, 24, 198, 51, 100}},
			{AttributeType: bgp.MP_REACH_NLRI, Attribute: []byte{0, 1, 1, 4, 10, 0, 0, 1, 0, 24, 192, 0, 2}},
		},
		BaseAttributes: &bgp.BaseAttributes{NHCAttr: nhcValue, NHC: nhc},
	}
	p.produceRouteMonitorMessage(bmp.Message{
		PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
		Payload:    &bmp.RouteMonitor{Update: update},
	})

	if len(publisher.msgs) != 2 {
		t.Fatalf("published %d messages, want 2", len(publisher.msgs))
	}
	messages := make(map[string]UnicastPrefix, 2)
	for _, published := range publisher.msgs {
		var message UnicastPrefix
		if err := json.Unmarshal(published.payload, &message); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		messages[message.Action] = message
	}
	added, ok := messages["add"]
	if !ok || added.Prefix != "192.0.2.0" || added.BaseAttributes == nil || added.BaseAttributes.NHC == nil {
		t.Fatalf("reachable NLRI not published with NHC: %+v", added)
	}
	withdrawn, ok := messages["del"]
	if !ok || withdrawn.Prefix != "198.51.100.0" || withdrawn.BaseAttributes == nil || withdrawn.BaseAttributes.NHC != nil || len(withdrawn.BaseAttributes.NHCAttr) != 0 || withdrawn.BaseAttributes.NHCMalformed || withdrawn.BaseAttributes.NHCEmpty || withdrawn.BaseAttributes.NHCDiscarded || withdrawn.BaseAttributes.NHCUnverified {
		t.Fatalf("unreachable NLRI not published without NHC: %+v", withdrawn)
	}
}
