package bmp

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// peerIdentityFmt is the fmt based PeerIdentity, the oracle for the
// allocation-free implementation.
func peerIdentityFmt(p *PerPeerHeader) string {
	switch p.PeerType {
	case PeerType0, PeerType1, PeerType2:
		return fmt.Sprintf("%d-%s-%s-%d-%s", p.PeerType, hex.EncodeToString(p.PeerDistinguisher), p.GetPeerAddrString(), p.PeerAS, p.GetPeerBGPIDString())
	case PeerType3:
		return fmt.Sprintf("%d-%s-%s", p.PeerType, hex.EncodeToString(p.PeerDistinguisher), p.GetPeerBGPIDString())
	default:
		return ""
	}
}

func TestPeerIdentityMatchesFmt(t *testing.T) {
	v6 := []byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	v4 := make([]byte, 16)
	copy(v4[12:], []byte{192, 0, 2, 1})
	rds := map[string][]byte{
		"zero":    make([]byte, 8),
		"nonzero": {0, 1, 0xfd, 0xe8, 0, 0, 0, 7},
		"max":     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"nil":     nil,
	}
	ids := map[string][]byte{"v4": {10, 0, 0, 1}, "v6": v6, "nil": nil}
	for _, pt := range []PeerType{PeerType0, PeerType1, PeerType2, PeerType3, 4, 255} {
		for rdName, rd := range rds {
			for idName, id := range ids {
				for _, as := range []uint32{0, 65000, 4294967295} {
					for _, addr := range [][]byte{v4, v6, nil} {
						for _, flagV := range []bool{false, true} {
							p := &PerPeerHeader{PeerType: pt, PeerDistinguisher: rd, PeerAddress: addr, PeerAS: as, PeerBGPID: id, flagV: flagV}
							if got, want := p.PeerIdentity(), peerIdentityFmt(p); got != want {
								t.Fatalf("type=%d rd=%s id=%s as=%d v=%t: got %q, want %q", pt, rdName, idName, as, flagV, got, want)
							}
						}
					}
				}
			}
		}
	}
}

func BenchmarkPeerIdentity(b *testing.B) {
	p := &PerPeerHeader{
		PeerType:          PeerType1,
		PeerDistinguisher: []byte{0, 1, 0xfd, 0xe8, 0, 0, 0, 7},
		PeerAddress:       []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		PeerAS:            65000,
		PeerBGPID:         []byte{10, 0, 0, 1},
		flagV:             true,
	}
	b.Run("fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = peerIdentityFmt(p)
		}
	})
	b.Run("buffer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = p.PeerIdentity()
		}
	})
}
