package bmp

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

var (
	ErrInvFlagRequestForPeerType = errors.New("unsupported request for the peer type")
)

const (
	BMP_PEER_HEADER_SIZE = 42
)

type PeerType uint8

const (
	PeerType0 PeerType = iota
	PeerType1
	PeerType2
	PeerType3
)

// PerPeerHeader defines BMP Per-Peer Header per rfc7854
type PerPeerHeader struct {
	PeerType PeerType
	// 	0 1 2 3 4 5 6 7
	// 	+-+-+-+-+-+-+-+-+
	// 	|F| | | | | | | |
	// 	+-+-+-+-+-+-+-+-+
	// *  The F flag indicates that the Loc-RIB is filtered.  This MUST be
	// set when a filter is applied to Loc-RIB routes sent to the BMP
	// collector.
	flagF             bool
	flagV             bool
	flagL             bool
	flagA             bool
	flagO             bool
	PeerDistinguisher []byte // *PeerDistinguisher
	PeerAddress       []byte
	PeerAS            uint32
	PeerBGPID         []byte
	PeerTimestamp     []byte
}

// Len returns the length of PerPeerHeader structure
func (p *PerPeerHeader) Len() int {
	return 1 + 1 + len(p.PeerDistinguisher) + len(p.PeerAddress) + 4 + len(p.PeerBGPID) + len(p.PeerTimestamp)
}

func peerType(b byte) (PeerType, error) {
	// Extracting Peer type
	// *  Peer Type = 0: Global Instance Peer
	// *  Peer Type = 1: RD Instance Peer
	// *  Peer Type = 2: Local Instance Peer
	// *  Peer Type = 3: Local RIB Peer, RFC9069
	switch PeerType(b) {
	case PeerType0:
		return PeerType0, nil
	case PeerType1:
		return PeerType1, nil
	case PeerType2:
		return PeerType2, nil
	case PeerType3:
		return PeerType3, nil
	default:
		return 0xff, fmt.Errorf("invalid peer type, expected between 0 and 3 found %d", b)
	}
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

// GetPeerBGPIDString returns a string representation of Peer BGP ID
func (p *PerPeerHeader) GetPeerBGPIDString() string {
	return net.IP(p.PeerBGPID).To4().String()
}

// GetPeerAddrString returns a string representation of Peer address
func (p *PerPeerHeader) GetPeerAddrString() string {
	if p.PeerType != PeerType3 && p.flagV {
		// IPv6 specific conversions
		return net.IP(p.PeerAddress).To16().String()
	}
	// IPv4 specific conversions
	return net.IP(p.PeerAddress[12:]).To4().String()
}

// IsAdjRIBOutPost returns true if PeerType is 0,1 or 2 and O flag is set, otherwise it returns error
func (p *PerPeerHeader) IsAdjRIBOutPost() (bool, error) {
	if p.PeerType != PeerType3 {
		return p.flagO, nil
	}

	return false, ErrInvFlagRequestForPeerType
}

// IsAdjRIBInPost returns true if PeerType is 0,1 or 2 and L flag is set, otherwise it returns error
func (p *PerPeerHeader) IsAdjRIBInPost() (bool, error) {
	if p.PeerType != PeerType3 {
		return p.flagL, nil
	}

	return false, ErrInvFlagRequestForPeerType
}

// IsLocRIBFiltered returns true if PeerType is 3 and F flag is set, otherwise it returns error
func (p *PerPeerHeader) IsLocRIBFiltered() (bool, error) {
	if p.PeerType == PeerType3 {
		return p.flagF, nil
	}

	return false, ErrInvFlagRequestForPeerType
}

// IsRemotePeerIPv6 returns true if Remote Peer is IPv6 for PeerType is 0,1 or 2, for Peer Type 3 always returns false.
func (p *PerPeerHeader) IsRemotePeerIPv6() bool {
	if p.PeerType != PeerType3 {
		return p.flagV
	}

	return false
}

// GetPeerDistinguisherString returns string representation of Peer's distinguisher
// depending on the peer's type.
func (p *PerPeerHeader) GetPeerDistinguisherString() string {
	pd := "0:0"
	switch p.PeerType {
	case PeerType0:
		break
	case PeerType1:
		fallthrough
	case PeerType3:
		if rd, err := base.MakeRD(p.PeerDistinguisher); err != nil {
			break
		} else {
			return rd.String()
		}
	case PeerType2:
		return strconv.FormatInt(int64(binary.BigEndian.Uint64(p.PeerDistinguisher)), 10)
	}

	return pd
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
	p := 0
	var err error
	if pph.PeerType, err = peerType(b[p]); err != nil {
		return nil, err
	}
	p++
	if pph.PeerType == PeerType3 {
		// Flag F is applicable only to Peer type 3
		pph.flagF = b[p]&0x80 == 0x80
	} else {
		// Flags V,L,A and O applicable ONLY to Peer Type 0, 1 and 2
		pph.flagV = b[p]&0x80 == 0x80
		pph.flagL = b[p]&0x40 == 0x40
		pph.flagA = b[p]&0x20 == 0x20
		pph.flagO = b[p]&0x10 == 0x10
	}
	p++
	// RD 8 bytes
	copy(pph.PeerDistinguisher, b[p:p+8])
	p += 8
	// Peer Address 16 bytes but for IPv4 case only last 4 bytes needed
	copy(pph.PeerAddress, b[p:p+16])
	p += 16
	pph.PeerAS = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	copy(pph.PeerBGPID, b[p:p+4])
	p += 4
	// Store Peer's timestamp (8 bytes) as a slice
	copy(pph.PeerTimestamp, b[p:p+8])

	return pph, nil
}
