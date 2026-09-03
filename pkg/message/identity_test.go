package message

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

const (
	defaultTestRouterIP   = "10.0.0.1"
	defaultTestRouterHash = "abc123"
)

func attachTestIdentity(ph *bmp.PerPeerHeader, routerIP, routerHash string) *bmp.PerPeerHeader {
	if ph == nil {
		return nil
	}

	ph.Identity = bmp.PeerIdentity{
		SpeakerIP:   routerIP,
		SpeakerHash: routerHash,
		RouterIP:    routerIP,
		RouterHash:  routerHash,
		PeerHash:    ph.GetPeerHash(),
		IsLocRIB:    ph.PeerType == bmp.PeerType3,
	}
	if ph.PeerType != bmp.PeerType3 {
		ph.Identity.PeerIP = ph.GetPeerAddrString()
	}

	return ph
}

func attachDefaultTestIdentity(ph *bmp.PerPeerHeader) *bmp.PerPeerHeader {
	return attachTestIdentity(ph, defaultTestRouterIP, defaultTestRouterHash)
}

func TestPeerIdentityKeyVariations(t *testing.T) {
	seen := make(map[string]bmp.PeerType)
	for _, peerType := range []bmp.PeerType{bmp.PeerType0, bmp.PeerType1, bmp.PeerType2, bmp.PeerType3} {
		ph := makePeerHeader(t, peerType, 0)
		key := ph.PeerIdentity()
		if key == "" {
			t.Fatalf("PeerIdentity() returned empty key for peer type %d", peerType)
		}
		if previous, ok := seen[key]; ok {
			t.Fatalf("PeerIdentity() key %q reused for peer types %d and %d", key, previous, peerType)
		}
		seen[key] = peerType
	}

	normal := makePeerHeader(t, bmp.PeerType0, 0)
	normalChanged := *normal
	normalChanged.PeerAddress = append([]byte(nil), normal.PeerAddress...)
	normalChanged.PeerAddress[15]++
	if normal.PeerIdentity() == normalChanged.PeerIdentity() {
		t.Fatal("Peer Type 0 identity key did not change when peer address changed")
	}

	locRIB := makePeerHeader(t, bmp.PeerType3, 0)
	locRIBChanged := *locRIB
	locRIBChanged.PeerAS++
	locRIBChanged.PeerAddress = append([]byte(nil), locRIB.PeerAddress...)
	locRIBChanged.PeerAddress[15]++
	if locRIB.PeerIdentity() != locRIBChanged.PeerIdentity() {
		t.Fatal("Peer Type 3 identity key changed when peer AS/address changed")
	}
}

func TestIdentityFromPeerUpVariations(t *testing.T) {
	t.Run("normal peer uses peer up local address as router", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    buildPeerUpMessage(t, "192.0.2.10"),
			SpeakerIP:  "10.2.1.3",
		}

		got := bmp.IdentityFromPeerUp(msg)
		if got.RouterIP != "192.0.2.10" {
			t.Errorf("RouterIP = %q, want %q", got.RouterIP, "192.0.2.10")
		}
		if got.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
		}
		if got.SpeakerIP != "10.2.1.3" {
			t.Errorf("SpeakerIP = %q, want %q", got.SpeakerIP, "10.2.1.3")
		}
		if got.IsLocRIB {
			t.Fatal("IsLocRIB = true, want false")
		}
	})

	t.Run("zero local address falls back to speaker", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		peerUp := buildPeerUpMessage(t, "0.0.0.0")
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    peerUp,
			SpeakerIP:  "10.2.1.3",
		}

		got := bmp.IdentityFromPeerUp(msg)
		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker IP %q", got.RouterIP, "10.2.1.3")
		}
		if got.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
		}
	})

	t.Run("loc rib uses speaker as router and empty peer ip", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType3, 0)
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    buildPeerUpMessage(t, "192.0.2.10"),
			SpeakerIP:  "10.2.1.3",
		}

		got := bmp.IdentityFromPeerUp(msg)
		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker IP %q", got.RouterIP, "10.2.1.3")
		}
		if got.PeerIP != "" {
			t.Errorf("PeerIP = %q, want empty Loc-RIB peer IP", got.PeerIP)
		}
		if !got.IsLocRIB {
			t.Fatal("IsLocRIB = false, want true")
		}
	})

	t.Run("missing peer header falls back to speaker only", func(t *testing.T) {
		got := bmp.IdentityFromPeerUp(bmp.Message{
			Payload:   buildPeerUpMessage(t, "192.0.2.10"),
			SpeakerIP: "10.2.1.3",
		})

		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker fallback", got.RouterIP)
		}
		if got.PeerIP != "" {
			t.Errorf("PeerIP = %q, want empty value without peer header", got.PeerIP)
		}
	})

	t.Run("invalid peer up payload falls back to peer header", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		got := bmp.IdentityFromPeerUp(bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.PeerDownMessage{},
			SpeakerIP:  "10.2.1.3",
		})

		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want peer-header fallback", got.RouterIP)
		}
		if got.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
		}
	})

	t.Run("malformed local address falls back to speaker", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		got := bmp.IdentityFromPeerUp(bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.PeerUpMessage{},
			SpeakerIP:  "10.2.1.3",
		})

		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker fallback", got.RouterIP)
		}
		if got.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
		}
	})
}

func TestIdentityFromPeerHeaderFallbackVariations(t *testing.T) {
	t.Run("normal peer fallback uses speaker as router", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		got := bmp.IdentityFromPeerHeader(bmp.Message{
			PeerHeader: ph,
			SpeakerIP:  "10.2.1.3",
		})

		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want %q", got.RouterIP, "10.2.1.3")
		}
		if got.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", got.PeerIP, ph.GetPeerAddrString())
		}
		if got.IsLocRIB {
			t.Fatal("IsLocRIB = true, want false")
		}
	})

	t.Run("loc rib fallback preserves empty peer ip", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType3, 0)
		got := bmp.IdentityFromPeerHeader(bmp.Message{
			PeerHeader: ph,
			SpeakerIP:  "10.2.1.3",
		})

		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want %q", got.RouterIP, "10.2.1.3")
		}
		if got.PeerIP != "" {
			t.Errorf("PeerIP = %q, want empty Loc-RIB peer IP", got.PeerIP)
		}
		if !got.IsLocRIB {
			t.Fatal("IsLocRIB = false, want true")
		}
	})

	t.Run("missing peer address does not panic", func(t *testing.T) {
		ph := &bmp.PerPeerHeader{
			PeerType:          bmp.PeerType0,
			PeerAS:            65000,
			PeerBGPID:         []byte{10, 0, 0, 1},
			PeerDistinguisher: make([]byte, 8),
			PeerTimestamp:     make([]byte, 8),
		}
		got := bmp.IdentityFromPeerHeader(bmp.Message{
			PeerHeader: ph,
			SpeakerIP:  "10.2.1.3",
		})

		if got.PeerIP != "" {
			t.Errorf("PeerIP = %q, want empty value for missing peer address", got.PeerIP)
		}
		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want %q", got.RouterIP, "10.2.1.3")
		}
	})

	t.Run("empty speaker identity does not panic", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		got := bmp.IdentityFromPeerHeader(bmp.Message{PeerHeader: ph})

		if got.RouterIP != "" {
			t.Errorf("RouterIP = %q, want empty value", got.RouterIP)
		}
		if got.SpeakerIP != "" {
			t.Errorf("SpeakerIP = %q, want empty value", got.SpeakerIP)
		}
		if got.RouterHash != "" {
			t.Errorf("RouterHash = %q, want empty value", got.RouterHash)
		}
		if got.SpeakerHash != "" {
			t.Errorf("SpeakerHash = %q, want empty value", got.SpeakerHash)
		}
	})

	t.Run("invalid speaker identity does not generate hashes", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		got := bmp.IdentityFromPeerHeader(bmp.Message{
			PeerHeader: ph,
			SpeakerIP:  "not-an-ip",
		})

		if got.RouterIP != "not-an-ip" {
			t.Errorf("RouterIP = %q, want original invalid value", got.RouterIP)
		}
		if got.RouterHash != "" {
			t.Errorf("RouterHash = %q, want empty value for invalid IP", got.RouterHash)
		}
		if got.SpeakerHash != "" {
			t.Errorf("SpeakerHash = %q, want empty value for invalid IP", got.SpeakerHash)
		}
	})
}

func TestProducerAttachIdentitySnapshot(t *testing.T) {
	t.Run("cached identity wins over speaker fallback", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		cached := attachTestIdentity(ph, "192.0.2.10", "cached-hash").Identity
		p.identities[ph.PeerIdentity()] = cached

		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{},
			SpeakerIP:  "10.2.1.3",
		}
		p.attachIdentitySnapshot(&msg)

		if msg.PeerHeader == ph {
			t.Fatal("PeerHeader pointer was reused, want an identity snapshot copy")
		}
		if msg.PeerHeader.Identity.RouterIP != "192.0.2.10" {
			t.Errorf("RouterIP = %q, want cached identity", msg.PeerHeader.Identity.RouterIP)
		}
		if msg.PeerHeader.Identity.RouterHash != "cached-hash" {
			t.Errorf("RouterHash = %q, want cached identity", msg.PeerHeader.Identity.RouterHash)
		}
	})

	t.Run("missing cache falls back to peer header", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{},
			SpeakerIP:  "10.2.1.3",
		}
		p.attachIdentitySnapshot(&msg)

		if msg.PeerHeader.Identity.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker fallback", msg.PeerHeader.Identity.RouterIP)
		}
		if msg.PeerHeader.Identity.PeerIP != ph.GetPeerAddrString() {
			t.Errorf("PeerIP = %q, want %q", msg.PeerHeader.Identity.PeerIP, ph.GetPeerAddrString())
		}
	})

	t.Run("missing cache loc rib keeps peer ip empty", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType3, 0)
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{},
			SpeakerIP:  "10.2.1.3",
		}
		p.attachIdentitySnapshot(&msg)

		if msg.PeerHeader.Identity.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker fallback", msg.PeerHeader.Identity.RouterIP)
		}
		if msg.PeerHeader.Identity.PeerIP != "" {
			t.Errorf("PeerIP = %q, want empty Loc-RIB peer IP", msg.PeerHeader.Identity.PeerIP)
		}
	})

	t.Run("nil and non peer messages are ignored", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		p.attachIdentitySnapshot(nil)

		msg := bmp.Message{Payload: &bmp.RawMessage{}, SpeakerIP: "10.2.1.3"}
		p.attachIdentitySnapshot(&msg)
		if msg.PeerHeader != nil {
			t.Fatal("PeerHeader was unexpectedly set")
		}
	})

	t.Run("unknown peer type uses fallback identity without cache key", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		ph := &bmp.PerPeerHeader{
			PeerType:          bmp.PeerTypeUnknown,
			PeerAddress:       make([]byte, 16),
			PeerDistinguisher: make([]byte, 8),
			PeerBGPID:         []byte{10, 0, 0, 1},
			PeerTimestamp:     make([]byte, 8),
		}
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{},
			SpeakerIP:  "10.2.1.3",
		}

		p.attachIdentitySnapshot(&msg)
		if msg.PeerHeader.Identity.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want speaker fallback", msg.PeerHeader.Identity.RouterIP)
		}
		if len(p.identities) != 0 {
			t.Fatalf("identity cache mutated for unknown peer type, len = %d", len(p.identities))
		}
	})
}

func TestProducingWorkerRefreshesIdentityAfterReady(t *testing.T) {
	rec := &recordingPublisher{}
	p := NewProducer(rec, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	cached := attachTestIdentity(ph, "192.0.2.10", "cached-router").Identity
	p.identities[ph.PeerIdentity()] = cached
	close(p.speakerReady)

	statValue := make([]byte, 4)
	binary.BigEndian.PutUint32(statValue, 42)
	msg := bmp.Message{
		PeerHeader: attachTestIdentity(ph, "10.2.1.3", "fallback-router"),
		Payload: &bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{
			{
				InformationType:   0,
				InformationLength: 4,
				Information:       statValue,
			},
		}},
		SpeakerIP: "10.2.1.3",
	}

	p.producingWorker(msg)

	if len(rec.msgs) != 1 {
		t.Fatalf("published messages = %d, want 1", len(rec.msgs))
	}
	var got Stats
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.RouterIP != "192.0.2.10" {
		t.Errorf("RouterIP = %q, want cached identity", got.RouterIP)
	}
	if got.RouterHash != "cached-router" {
		t.Errorf("RouterHash = %q, want cached identity", got.RouterHash)
	}
}

func TestProducePeerMessageIdentityCornerCases(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)

	t.Run("nil peer header returns error", func(t *testing.T) {
		if _, err := p.producePeerMessage(peerUP, bmp.Message{Payload: buildPeerUpMessage(t, "192.0.2.10")}, bmp.PeerIdentity{}); err == nil {
			t.Fatal("producePeerMessage() error = nil, want error")
		}
	})

	t.Run("invalid peer up payload returns error", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		if _, err := p.producePeerMessage(peerUP, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{}}, ph.Identity); err == nil {
			t.Fatal("producePeerMessage() error = nil, want error")
		}
	})

	t.Run("invalid peer down payload returns error", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		if _, err := p.producePeerMessage(peerDown, bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.10")}, ph.Identity); err == nil {
			t.Fatal("producePeerMessage() error = nil, want error")
		}
	})

	t.Run("loc rib peer down keeps remote ip empty", func(t *testing.T) {
		ph := makePeerHeader(t, bmp.PeerType3, 0)
		peer := attachTestIdentity(ph, "10.2.1.3", "router-hash").Identity
		msg := bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.PeerDownMessage{Reason: 1},
			SpeakerIP:  "10.2.1.3",
		}

		got, err := p.producePeerMessage(peerDown, msg, peer)
		if err != nil {
			t.Fatalf("producePeerMessage() error = %v", err)
		}
		if got.RouterIP != "10.2.1.3" {
			t.Errorf("RouterIP = %q, want %q", got.RouterIP, "10.2.1.3")
		}
		if got.RemoteIP != "" {
			t.Errorf("RemoteIP = %q, want empty Loc-RIB remote IP", got.RemoteIP)
		}
	})

	t.Run("unknown peer up does not cache empty key", func(t *testing.T) {
		p := NewProducer(&mockPublisher{}, false).(*producer)
		ph := &bmp.PerPeerHeader{
			PeerType:          bmp.PeerTypeUnknown,
			PeerAddress:       make([]byte, 16),
			PeerDistinguisher: make([]byte, 8),
			PeerBGPID:         []byte{10, 0, 0, 1},
			PeerTimestamp:     make([]byte, 8),
		}

		p.producingWorker(bmp.Message{
			PeerHeader: ph,
			Payload:    buildPeerUpMessage(t, "192.0.2.10"),
			SpeakerIP:  "10.2.1.3",
		})

		if len(p.identities) != 0 {
			t.Fatalf("identity cache len = %d, want 0", len(p.identities))
		}
		if _, ok := p.identities[""]; ok {
			t.Fatal("identity cache contains an empty key")
		}
	})
}
