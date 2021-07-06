package bmp

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

const (
	BMP_PEER_HEADER_SIZE = 42
)

// PerPeerHeader defines BMP Per-Peer Header per rfc7854
type PerPeerHeader struct {
	PeerType          byte
	FlagV             bool
	FlagL             bool
	FlagA             bool
	FlagO             bool
	PeerDistinguisher []byte // *PeerDistinguisher
	PeerAddress       []byte
	PeerAS            int32
	PeerBGPID         []byte
	PeerTimestamp     []byte
}

// Len returns the length of PerPeerHeader structure
func (p *PerPeerHeader) Len() int {
	return 1 + 1 + len(p.PeerDistinguisher) + len(p.PeerAddress) + 4 + len(p.PeerBGPID) + len(p.PeerTimestamp)
}

// Serialize generate a slice of bytes for sending over the network
func (p *PerPeerHeader) Serialize() ([]byte, error) {
	b := make([]byte, BMP_PEER_HEADER_SIZE)
	b[0] = p.PeerType
	flag := uint8(0)
	if p.FlagV {
		flag |= 0x80
	}
	if p.FlagL {
		flag |= 0x40
	}
	if p.FlagA {
		flag |= 0x20
	}
	if p.FlagO {
		flag |= 0x10
	}
	b[1] = flag
	copy(b[2:10], p.PeerDistinguisher)
	if p.FlagV {
		copy(b[10:26], p.PeerAddress)
	} else {
		// Copying only last 4 bytes where IPv4 address is stored
		copy(b[22:26], p.PeerAddress[12:16])
	}
	binary.BigEndian.PutUint32(b[26:30], uint32(p.PeerAS))
	copy(b[30:34], p.PeerBGPID)
	copy(b[34:42], p.PeerTimestamp)

	return b, nil
}

// UnmarshalPerPeerHeader processes Per-Peer header
func UnmarshalPerPeerHeader(b []byte) (*PerPeerHeader, error) {
	if glog.V(6) {
		glog.Infof("BMP Per Peer Header Raw: %s", tools.MessageHex(b))
	}
	pph := &PerPeerHeader{
		PeerDistinguisher: make([]byte, 8), // newPeerDistinguisher(),
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerTimestamp:     make([]byte, 8),
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
	p := 0
	pph.PeerType = b[p]
	p++
	pph.FlagV = b[p]&0x80 == 0x80
	pph.FlagL = b[p]&0x40 == 0x40
	pph.FlagA = b[p]&0x20 == 0x20
	pph.FlagO = b[p]&0x10 == 0x10
	p++
	// RD 8 bytes
	copy(pph.PeerDistinguisher, b[p:p+8])
	p += 8
	// Peer Address 16 bytes but for IPv4 case only last 4 bytes needed
	copy(pph.PeerAddress, b[p:p+16])
	p += 16
	pph.PeerAS = int32(binary.BigEndian.Uint32(b[p : p+4]))
	p += 4
	copy(pph.PeerBGPID, b[p:p+4])
	p += 4
	// Store Peer's timestamp (8 bytes) as a slice
	copy(pph.PeerTimestamp, b[p:p+8])

	return pph, nil
}

func (p *PerPeerHeader) GetPeerTimestamp() string {
	t := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	ts := time.Second * time.Duration(binary.BigEndian.Uint32(p.PeerTimestamp[0:4]))
	tms := time.Duration(int(binary.BigEndian.Uint32(p.PeerTimestamp[4:8])))
	t = t.Add(ts)
	t = t.Add(tms)
	return t.Format(time.RFC3339Nano)
}

// GetPeerHash calculates Peer Hash and returns as a hex string
func (p *PerPeerHeader) GetPeerHash() string {
	data := []byte{}
	data = append(data, p.PeerDistinguisher...)
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

// GetPeerDistinguisherString returns string representation of Peer's distinguisher
// depending on the peer's type.
func (p *PerPeerHeader) GetPeerDistinguisherString() string {
	var s string
	switch p.PeerType {
	case 0:
		s += "0:0"
	case 1:
		if rd, err := base.MakeRD(p.PeerDistinguisher); err != nil {
			s += "0:0"
			break
		} else {
			s += rd.String()
		}
	case 2:
		s += fmt.Sprintf("%d", binary.BigEndian.Uint64(p.PeerDistinguisher))
	}

	return s
}
