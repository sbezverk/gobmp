package bmp

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// PerPeerHeader defines BMP Per-Peer Header per rfc7854
type PerPeerHeader struct {
	PeerType          byte
	FlagV             bool
	FlagL             bool
	FlagA             bool
	PeerDistinguisher []byte
	PeerAddress       []byte
	PeerAS            int32
	PeerBGPID         []byte
	PeerTimestamp     time.Duration
}

// UnmarshalPerPeerHeader processes Per-Peer header
func UnmarshalPerPeerHeader(b []byte) (*PerPeerHeader, error) {
	glog.V(6).Infof("BMP Per Peer Header Raw: %s", internal.MessageHex(b))
	pph := &PerPeerHeader{
		PeerDistinguisher: make([]byte, 8),
		PeerAddress:       make([]byte, 14),
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
	copy(pph.PeerDistinguisher, b[4:12])
	// Peer Address 16 bytes
	copy(pph.PeerAddress, b[12:26])
	pph.PeerAS = int32(binary.BigEndian.Uint32(b[26:30]))
	copy(pph.PeerBGPID, b[30:34])
	pph.PeerTimestamp = time.Duration(binary.BigEndian.Uint64(b[34:42]))

	return pph, nil
}
