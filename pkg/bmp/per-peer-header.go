package bmp

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PeerDistinguisher defines an object for Peer's Distinguisher manipulations
type PeerDistinguisher struct {
	pd []byte
}

func (pd *PeerDistinguisher) String() string {
	var s string
	v := binary.BigEndian.Uint64(pd.pd)
	if v == 0 {
		return "0:0"
	}
	s = "not implemented"

	return s
}

func (pd *PeerDistinguisher) copy(b []byte) {
	if pd.pd == nil || len(pd.pd) == 0 {
		return
	}
	copy(pd.pd, b[:len(pd.pd)-1])
}

func newPeerDistinguisher() *PeerDistinguisher {
	return &PeerDistinguisher{
		pd: make([]byte, 8),
	}
}

// PerPeerHeader defines BMP Per-Peer Header per rfc7854
type PerPeerHeader struct {
	PeerType          byte
	FlagV             bool
	FlagL             bool
	FlagA             bool
	PeerDistinguisher *PeerDistinguisher
	PeerAddress       []byte
	PeerAS            int32
	PeerBGPID         []byte
	PeerTimestamp     string
}

// UnmarshalPerPeerHeader processes Per-Peer header
func UnmarshalPerPeerHeader(b []byte) (*PerPeerHeader, error) {
	glog.V(6).Infof("BMP Per Peer Header Raw: %s", tools.MessageHex(b))
	pph := &PerPeerHeader{
		PeerDistinguisher: newPeerDistinguisher(),
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
	}
	// Extracting Peer type
	// *  Peer Type = 0: Global Instance Peer
	// *  Peer Type = 1: RD Instance Peer
	// *  Peer Type = 2: Local Instance Peer
	switch b[0] {
	case 0:
	case 1:
	case 2:
	default:
		return nil, fmt.Errorf("invalid peer type, expected between 0 and 2 found %d", b[0])
	}
	pph.PeerType = b[0]
	pph.FlagV = b[1]&0x80 == 0x80
	pph.FlagL = b[1]&0x40 == 0x40
	pph.FlagA = b[1]&0x20 == 0x20
	// RD 8 bytes
	pph.PeerDistinguisher.copy(b[2:10])
	// Peer Address 16 bytes but for IPv4 case only last 4 bytes needed
	copy(pph.PeerAddress, b[10:26])
	pph.PeerAS = int32(binary.BigEndian.Uint32(b[26:30]))
	copy(pph.PeerBGPID, b[30:34])
	t := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	ts := time.Second * time.Duration(binary.BigEndian.Uint32(b[34:38]))
	tms := time.Duration(int(binary.BigEndian.Uint32(b[38:42])))
	t = t.Add(ts)
	t = t.Add(tms)
	pph.PeerTimestamp = t.Format(time.StampMicro)

	return pph, nil
}

// GetPeerHash calculates Peer Hash and returns as a hex string
func (p *PerPeerHeader) GetPeerHash() string {
	data := []byte{}
	data = append(data, p.PeerAddress...)
	data = append(data, []byte(fmt.Sprintf("%d", p.PeerAS))...)
	data = append(data, p.PeerBGPID...)

	return fmt.Sprintf("%x", md5.Sum(data))
}

// GetPeerAddrString returns a string representation of Peer address
func (p *PerPeerHeader) GetPeerAddrString() string {
	if p.FlagV {
		// IPv6 specific conversions
		return net.IP(p.PeerAddress).To16().String()
	}
	// IPv4 specific conversions
	return net.IP(p.PeerAddress[12:]).To4().String()
}
