package bmp

import "testing"

func testPeerHeader(t *testing.T, peerType PeerType, peerAddr []byte, peerAS uint32, bgpID []byte) *PerPeerHeader {
	t.Helper()
	ph := &PerPeerHeader{
		PeerType:          peerType,
		PeerDistinguisher: make([]byte, 8),
		PeerAddress:       make([]byte, 16),
		PeerAS:            peerAS,
		PeerBGPID:         append([]byte(nil), bgpID...),
		PeerTimestamp:     make([]byte, 8),
	}
	if len(peerAddr) == 4 {
		copy(ph.PeerAddress[12:], peerAddr)
	} else {
		copy(ph.PeerAddress, peerAddr)
	}
	return ph
}

func testPeerUp(localIP []byte) *PeerUpMessage {
	peerUp := &PeerUpMessage{
		LocalAddress: make([]byte, 16),
	}
	if len(localIP) == 4 {
		copy(peerUp.LocalAddress[12:], localIP)
	} else {
		copy(peerUp.LocalAddress, localIP)
	}
	return peerUp
}

func TestPeerIdentityKeyAndComparison(t *testing.T) {
	normal := testPeerHeader(t, PeerType0, []byte{192, 0, 2, 1}, 65000, []byte{10, 0, 0, 1})
	normalChanged := *normal
	normalChanged.PeerAddress = append([]byte(nil), normal.PeerAddress...)
	normalChanged.PeerAddress[15]++
	if normal.PeerIdentity() == normalChanged.PeerIdentity() {
		t.Fatal("PeerIdentity() did not change for PeerType0 peer address change")
	}

	locRIB := testPeerHeader(t, PeerType3, []byte{192, 0, 2, 1}, 65000, []byte{10, 0, 0, 1})
	locRIBChanged := *locRIB
	locRIBChanged.PeerAddress = append([]byte(nil), locRIB.PeerAddress...)
	locRIBChanged.PeerAddress[15]++
	locRIBChanged.PeerAS++
	if locRIB.PeerIdentity() != locRIBChanged.PeerIdentity() {
		t.Fatal("PeerIdentity() changed for Loc-RIB peer address/ASN change")
	}

	if got := (&PerPeerHeader{PeerType: PeerTypeUnknown}).PeerIdentity(); got != "" {
		t.Fatalf("PeerIdentity() = %q, want empty key for unknown peer type", got)
	}

	one := PeerIdentity{SpeakerIP: "10.0.0.1", RouterIP: "192.0.2.1", PeerIP: "192.0.2.2"}
	two := one
	if !one.IsEqual(two) {
		t.Fatal("IsEqual() returned false for identical identities")
	}
	two.PeerIP = "192.0.2.3"
	if one.IsEqual(two) {
		t.Fatal("IsEqual() returned true for different identities")
	}
	if one.String() == "" {
		t.Fatal("String() returned empty value")
	}
}

func TestIdentityFromPeerUp(t *testing.T) {
	ph := testPeerHeader(t, PeerType0, []byte{192, 0, 2, 2}, 65000, []byte{10, 0, 0, 1})
	got := IdentityFromPeerUp(Message{
		PeerHeader: ph,
		Payload:    testPeerUp([]byte{192, 0, 2, 1}),
		SpeakerIP:  "10.1.1.3",
	})
	if got.RouterIP != "192.0.2.1" {
		t.Fatalf("RouterIP = %q, want PeerUp local address", got.RouterIP)
	}
	if got.RouterHash != md5Hex("192.0.2.1") {
		t.Fatalf("RouterHash = %q, want md5 of router IP", got.RouterHash)
	}
	if got.PeerIP != "192.0.2.2" {
		t.Fatalf("PeerIP = %q, want peer header address", got.PeerIP)
	}

	got = IdentityFromPeerUp(Message{
		PeerHeader: ph,
		Payload:    testPeerUp([]byte{0, 0, 0, 0}),
		SpeakerIP:  "10.1.1.3",
	})
	if got.RouterIP != "10.1.1.3" {
		t.Fatalf("RouterIP = %q, want speaker fallback", got.RouterIP)
	}

	got = IdentityFromPeerUp(Message{
		PeerHeader: ph,
		Payload:    testPeerUp([]byte{0, 0, 0, 0}),
	})
	if got.RouterIP != "0.0.0.0" {
		t.Fatalf("RouterIP = %q, want original unspecified local address", got.RouterIP)
	}
	if got.RouterHash != "" {
		t.Fatalf("RouterHash = %q, want empty hash for unspecified router IP", got.RouterHash)
	}
}

func TestIdentityFromPeerUpLocRIBAndMalformed(t *testing.T) {
	locRIB := testPeerHeader(t, PeerType3, []byte{192, 0, 2, 2}, 65000, []byte{10, 0, 0, 1})
	got := IdentityFromPeerUp(Message{
		PeerHeader: locRIB,
		Payload:    testPeerUp([]byte{0, 0, 0, 0}),
		SpeakerIP:  "10.1.1.3",
	})
	if got.RouterIP != "10.1.1.3" {
		t.Fatalf("RouterIP = %q, want speaker fallback for Loc-RIB", got.RouterIP)
	}
	if got.PeerIP != "" {
		t.Fatalf("PeerIP = %q, want empty Loc-RIB peer IP", got.PeerIP)
	}
	if !got.IsLocRIB {
		t.Fatal("IsLocRIB = false, want true")
	}

	got = IdentityFromPeerUp(Message{Payload: testPeerUp([]byte{192, 0, 2, 1}), SpeakerIP: "10.1.1.3"})
	if got.RouterIP != "10.1.1.3" || got.PeerIP != "" {
		t.Fatalf("IdentityFromPeerUp without peer header = %+v, want speaker-only fallback", got)
	}

	got = IdentityFromPeerUp(Message{PeerHeader: locRIB, Payload: &PeerDownMessage{}, SpeakerIP: "10.1.1.3"})
	if got.RouterIP != "10.1.1.3" || got.PeerIP != "" {
		t.Fatalf("IdentityFromPeerUp with wrong payload = %+v, want peer-header fallback", got)
	}

	got = IdentityFromPeerUp(Message{PeerHeader: locRIB, Payload: &PeerUpMessage{}, SpeakerIP: "10.1.1.3"})
	if got.RouterIP != "10.1.1.3" {
		t.Fatalf("RouterIP = %q, want malformed PeerUp local address fallback", got.RouterIP)
	}
}

func TestIdentityFromPeerHeader(t *testing.T) {
	ph := testPeerHeader(t, PeerType0, []byte{192, 0, 2, 2}, 65000, []byte{10, 0, 0, 1})
	got := IdentityFromPeerHeader(Message{PeerHeader: ph, SpeakerIP: "10.1.1.3"})
	if got.RouterIP != "10.1.1.3" {
		t.Fatalf("RouterIP = %q, want speaker fallback", got.RouterIP)
	}
	if got.RouterHash != md5Hex("10.1.1.3") {
		t.Fatalf("RouterHash = %q, want md5 of speaker IP", got.RouterHash)
	}
	if got.PeerHash == "" {
		t.Fatal("PeerHash is empty")
	}

	got = IdentityFromPeerHeader(Message{PeerHeader: ph})
	if got.RouterIP != "" || got.RouterHash != "" || got.SpeakerHash != "" {
		t.Fatalf("empty speaker identity = %+v, want empty router/speaker hashes", got)
	}

	got = IdentityFromPeerHeader(Message{PeerHeader: ph, SpeakerIP: "not-an-ip"})
	if got.RouterIP != "not-an-ip" {
		t.Fatalf("RouterIP = %q, want original invalid speaker value", got.RouterIP)
	}
	if got.RouterHash != "" || got.SpeakerHash != "" {
		t.Fatalf("invalid speaker identity = %+v, want empty hashes", got)
	}

	got = IdentityFromPeerHeader(Message{SpeakerIP: "10.1.1.3"})
	if got.RouterIP != "10.1.1.3" || got.PeerHash != "" || got.PeerIP != "" {
		t.Fatalf("nil peer header identity = %+v, want speaker-only fallback", got)
	}
}
