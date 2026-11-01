package bmp

import "testing"

func TestPeerIdentityUsesRawDistinguisher(t *testing.T) {
	pairs := [][2][]byte{
		{{0, 3, 0, 0, 0, 0, 0, 1}, {0, 3, 0, 0, 0, 0, 0, 2}},
		{{0, 0, 0xfd, 0xe8, 0, 0, 0, 1}, {0, 2, 0, 0, 0xfd, 0xe8, 0, 1}},
	}
	for _, peerType := range []PeerType{PeerType0, PeerType1, PeerType2, PeerType3} {
		for _, pair := range pairs {
			first := testPeerHeader(t, peerType, []byte{192, 0, 2, 2}, 65000, []byte{10, 0, 0, 1})
			second := *first
			first.PeerDistinguisher, second.PeerDistinguisher = pair[0], pair[1]
			if first.PeerIdentity() == second.PeerIdentity() {
				t.Errorf("peer type %d merged distinguishers %x and %x", peerType, pair[0], pair[1])
			}
			if peerType == PeerType3 && first.GetTableKey() == second.GetTableKey() {
				t.Errorf("Loc-RIB table keys merged distinguishers %x and %x", pair[0], pair[1])
			}
		}
	}
}

func TestRawPeerKeysPreservePublishedDistinguisherAndHash(t *testing.T) {
	cases := []struct {
		pd   []byte
		hash string
	}{
		{[]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 1}, "04648f72bd42aa0f573109334d01ea10"},
		{[]byte{0, 2, 0, 0, 0xfd, 0xe8, 0, 1}, "97240dd22a530b89e695401f4d68dd1e"},
	}
	for _, tc := range cases {
		ph := testPeerHeader(t, PeerType1, []byte{0, 0, 0, 0}, 65000, []byte{10, 0, 0, 1})
		ph.PeerDistinguisher = tc.pd
		if got := ph.GetPeerDistinguisherString(); got != "65000:1" {
			t.Errorf("published peer_rd = %q, want 65000:1", got)
		}
		if got := ph.GetPeerHash(); got != tc.hash {
			t.Errorf("published peer hash = %q, want baseline %q", got, tc.hash)
		}
	}
}
