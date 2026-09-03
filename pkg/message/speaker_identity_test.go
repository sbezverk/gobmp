package message

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// assertSpeakerReady fails unless the producer released the route monitor and
// stats goroutines waiting on the first PeerUp.  Choosing a different address
// for the speaker must never turn into a decision not to latch at all: those
// goroutines block on this channel and would never produce a message again.
func assertSpeakerReady(t *testing.T, p *producer) {
	t.Helper()
	select {
	case <-p.speakerReady:
	default:
		t.Fatal("speakerReady is still open after PeerUp, route monitor messages would block forever")
	}
}

// publishPeerUp feeds one PeerUp through the producer and returns the
// PeerStateChange a consumer receives.
func publishPeerUp(t *testing.T, p *producer, peerType bmp.PeerType, localIP, connIP string) PeerStateChange {
	t.Helper()
	rec := p.publisher.(*recordingPublisher)

	p.producingWorker(bmp.Message{
		PeerHeader: makePeerHeader(t, peerType, 0x00),
		Payload:    buildPeerUpMessage(t, localIP),
		SpeakerIP:  connIP,
	})

	if len(rec.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(rec.msgs))
	}
	var got PeerStateChange
	if err := json.Unmarshal(rec.msgs[0].payload, &got); err != nil {
		t.Fatalf("unmarshal published message failed: %v", err)
	}
	return got
}

// TestSpeakerAddress covers the address selection itself.
func TestSpeakerAddress(t *testing.T) {
	tests := []struct {
		name    string
		localIP string
		connIP  string
		want    string
	}{
		{
			name:    "Peer Up local address wins",
			localIP: "192.168.1.1",
			connIP:  "10.20.0.1",
			want:    "192.168.1.1",
		},
		{
			name:    "zero-filled IPv4 local address falls back to the connection",
			localIP: "0.0.0.0",
			connIP:  "10.20.0.1",
			want:    "10.20.0.1",
		},
		{
			name:    "zero-filled IPv6 local address falls back to the connection",
			localIP: "::",
			connIP:  "2001:db8:20::1",
			want:    "2001:db8:20::1",
		},
		{
			name:    "absent local address falls back to the connection",
			localIP: "",
			connIP:  "10.20.0.1",
			want:    "10.20.0.1",
		},
		{
			name:    "local address is kept when the connection address is absent",
			localIP: "192.168.1.1",
			connIP:  "",
			want:    "192.168.1.1",
		},
		{
			name:    "neither identifies a host, the Peer Up value is kept",
			localIP: "0.0.0.0",
			connIP:  "",
			want:    "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := speakerAddress(tt.localIP, tt.connIP); got != tt.want {
				t.Errorf("speakerAddress(%q, %q) = %q, want %q", tt.localIP, tt.connIP, got, tt.want)
			}
		})
	}
}

// TestSpeakerIdentity_LocRIBPeerUpUsesConnectionAddress verifies that a PeerUp
// describing a Loc-RIB Instance Peer, which RFC 9069 Section 5.2 zero-fills,
// does not latch the speaker onto the unspecified address.
func TestSpeakerIdentity_LocRIBPeerUpUsesConnectionAddress(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)

	got := publishPeerUp(t, p, bmp.PeerType3, "0.0.0.0", "10.20.0.1")

	if got.RouterIP != "10.20.0.1" {
		t.Errorf("RouterIP = %q, want %q", got.RouterIP, "10.20.0.1")
	}
	if want := md5Hex("10.20.0.1"); got.RouterHash != want {
		t.Errorf("RouterHash = %q, want %q", got.RouterHash, want)
	}
	assertSpeakerReady(t, p)
}

// TestSpeakerIdentity_TwoLocRIBSpeakersStayDistinct is the regression this fix
// exists for.  The server builds one producer per connection, so two speakers
// whose first PeerUp is a Loc-RIB one used to latch on the same zero-filled
// address and hash identically.  A collector keyed on router_hash then merged
// their tables: observations of the same peer collapsed onto one entry, and a
// PeerDown from one speaker flushed routes the other was still reporting.
func TestSpeakerIdentity_TwoLocRIBSpeakersStayDistinct(t *testing.T) {
	speakers := []string{"10.20.0.1", "10.20.0.2"}
	hashes := make([]string, 0, len(speakers))

	for _, connIP := range speakers {
		p := NewProducer(&recordingPublisher{}, false).(*producer)

		got := publishPeerUp(t, p, bmp.PeerType3, "0.0.0.0", connIP)

		if want := md5Hex(connIP); got.RouterHash != want {
			t.Errorf("speaker %s: RouterHash = %q, want %q", connIP, got.RouterHash, want)
		}
		hashes = append(hashes, got.RouterHash)
	}

	if hashes[0] == hashes[1] {
		t.Fatalf("both speakers hashed to %q, they are indistinguishable to a collector", hashes[0])
	}
}

// TestSpeakerIdentity_EstablishedSessionUnchanged pins the behaviour every
// existing consumer already sees: when the PeerUp carries a local address, it
// remains the speaker identity and the connection address is not consulted.
func TestSpeakerIdentity_EstablishedSessionUnchanged(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)

	got := publishPeerUp(t, p, bmp.PeerType0, "192.168.1.1", "10.20.0.1")

	if got.RouterIP != "192.168.1.1" {
		t.Errorf("RouterIP = %q, want %q", got.RouterIP, "192.168.1.1")
	}
	if want := md5Hex("192.168.1.1"); got.RouterHash != want {
		t.Errorf("RouterHash = %q, want %q", got.RouterHash, want)
	}
	assertSpeakerReady(t, p)
}

// TestSpeakerIdentity_NoConnectionAddress covers the case where nothing
// identifies the speaker: the message keeps the address the PeerUp reported,
// and the producer still latches so route production is not blocked.
func TestSpeakerIdentity_NoConnectionAddress(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)

	got := publishPeerUp(t, p, bmp.PeerType3, "0.0.0.0", "")

	if got.RouterIP != "0.0.0.0" {
		t.Errorf("RouterIP = %q, want %q", got.RouterIP, "0.0.0.0")
	}
	assertSpeakerReady(t, p)
}
