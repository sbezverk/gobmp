package bmp

import "testing"

func TestMemoizeStrings(t *testing.T) {
	type strs struct{ hash, bgpID, addr, ts string }
	get := func(p *PerPeerHeader) strs {
		return strs{p.GetPeerHash(), p.GetPeerBGPIDString(), p.GetPeerAddrString(), p.GetPeerTimestamp()}
	}
	b := []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 7}
	b = append(b, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1)
	b = append(b, 0, 0, 0xfd, 0xe8, 10, 0, 0, 1, 0x68, 0, 0, 1, 0, 1, 0, 2)
	p, err := UnmarshalPerPeerHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	want := get(p)
	p.MemoizeStrings()
	if got := get(p); got != want {
		t.Fatalf("memoized %+v, want %+v", got, want)
	}
	// A copy modified afterwards computes its own strings.
	c := *p
	c.PeerBGPID = []byte{10, 0, 0, 9}
	if got := c.GetPeerBGPIDString(); got != "10.0.0.9" {
		t.Fatalf("copy: BGP ID %q", got)
	}
	// A short timestamp is left to GetPeerTimestamp, which panics on it.
	s := &PerPeerHeader{PeerAddress: make([]byte, 16), PeerBGPID: make([]byte, 4)}
	s.MemoizeStrings()
	defer func() {
		if recover() == nil {
			t.Fatal("GetPeerTimestamp() of a short timestamp did not panic")
		}
	}()
	s.GetPeerTimestamp()
}
