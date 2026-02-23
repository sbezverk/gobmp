package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// McastLeave defines EVPN Type 8 - Multicast Leave Synch Route
// RFC 9251 Section 9.3
type McastLeave struct {
	RD                *base.RD
	ESI               *ESI
	EthTag            []byte // 4 bytes
	McastSrcLen       uint8  // Length in bits: 0, 32, or 128
	McastSrcAddr      []byte // 0, 4, or 16 bytes based on McastSrcLen
	McastGrpLen       uint8  // Length in bits: 32 or 128
	McastGrpAddr      []byte // 4 or 16 bytes based on McastGrpLen
	OriginatorRtrLen  uint8  // Length in bits: 32 or 128
	OriginatorRtrAddr []byte // 4 or 16 bytes based on OriginatorRtrLen
	Reserved          []byte // 4 bytes
	MaxResponseTime   uint8  // 1 byte
	Flags             uint8  // 1 byte
}

// GetRouteTypeSpec returns the route type spec object
func (m *McastLeave) GetRouteTypeSpec() interface{} {
	return m
}

// getRD returns Route Distinguisher as a string
func (m *McastLeave) getRD() string {
	return m.RD.String()
}

// getESI returns Ethernet Segment Identifier
func (m *McastLeave) getESI() *ESI {
	return m.ESI
}

// getTag returns Ethernet Tag ID
func (m *McastLeave) getTag() []byte {
	return m.EthTag
}

// getMAC returns nil as Type 8 does not have MAC
func (m *McastLeave) getMAC() *MACAddress {
	return nil
}

// getMACLength returns nil as Type 8 does not have MAC
func (m *McastLeave) getMACLength() *uint8 {
	return nil
}

// getIPAddress returns nil as Type 8 does not have IP address
func (m *McastLeave) getIPAddress() []byte {
	return nil
}

// getIPLength returns nil as Type 8 does not have IP length
func (m *McastLeave) getIPLength() *uint8 {
	return nil
}

// getGWAddress returns nil as Type 8 does not have gateway address
func (m *McastLeave) getGWAddress() []byte {
	return nil
}

// getLabel returns nil as Type 8 does not have labels
func (m *McastLeave) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNMcastLeave parses EVPN Type 8 Multicast Leave Synch Route from wire format
// RFC 9251 Section 9.3
func UnmarshalEVPNMcastLeave(b []byte) (*McastLeave, error) {
	// Minimum length:
	// RD(8) + ESI(10) + EthTag(4) + McastSrcLen(1) + McastGrpLen(1) + McastGrpAddr(4) +
	// OriginatorRtrLen(1) + OriginatorRtrAddr(4) + Reserved(4) + MaxResponseTime(1) + Flags(1) = 39 bytes
	if len(b) < 39 {
		return nil, fmt.Errorf("invalid length of Multicast Leave Synch route: need at least 39 bytes, have %d", len(b))
	}

	m := &McastLeave{}
	p := 0

	// Parse RD (8 bytes)
	if p+8 > len(b) {
		return nil, fmt.Errorf("truncated at RD")
	}
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	m.RD = rd
	p += 8

	// Parse ESI (10 bytes)
	if p+10 > len(b) {
		return nil, fmt.Errorf("truncated at ESI")
	}
	esi, err := MakeESI(b[p : p+10])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ESI: %w", err)
	}
	m.ESI = esi
	p += 10

	// Parse Ethernet Tag ID (4 bytes)
	if p+4 > len(b) {
		return nil, fmt.Errorf("truncated at ethernet tag")
	}
	m.EthTag = make([]byte, 4)
	copy(m.EthTag, b[p:p+4])
	p += 4

	// Parse Multicast Source Length (1 byte)
	m.McastSrcLen = b[p]
	p++

	// Validate and parse Multicast Source Address
	var mcastSrcBytes int
	switch m.McastSrcLen {
	case 0:
		mcastSrcBytes = 0
	case 32:
		mcastSrcBytes = 4
	case 128:
		mcastSrcBytes = 16
	default:
		return nil, fmt.Errorf("invalid multicast source length: %d (must be 0, 32, or 128)", m.McastSrcLen)
	}

	if p+mcastSrcBytes > len(b) {
		return nil, fmt.Errorf("truncated multicast source address: need %d bytes, have %d", mcastSrcBytes, len(b)-p)
	}

	if mcastSrcBytes > 0 {
		m.McastSrcAddr = make([]byte, mcastSrcBytes)
		copy(m.McastSrcAddr, b[p:p+mcastSrcBytes])
		p += mcastSrcBytes
	}

	// Parse Multicast Group Length (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at multicast group length")
	}
	m.McastGrpLen = b[p]
	p++

	// Validate and parse Multicast Group Address
	var mcastGrpBytes int
	switch m.McastGrpLen {
	case 32:
		mcastGrpBytes = 4
	case 128:
		mcastGrpBytes = 16
	default:
		return nil, fmt.Errorf("invalid multicast group length: %d (must be 32 or 128)", m.McastGrpLen)
	}

	if p+mcastGrpBytes > len(b) {
		return nil, fmt.Errorf("truncated multicast group address: need %d bytes, have %d", mcastGrpBytes, len(b)-p)
	}

	m.McastGrpAddr = make([]byte, mcastGrpBytes)
	copy(m.McastGrpAddr, b[p:p+mcastGrpBytes])
	p += mcastGrpBytes

	// Parse Originator Router Length (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at originator router length")
	}
	m.OriginatorRtrLen = b[p]
	p++

	// Validate and parse Originator Router Address
	var originatorBytes int
	switch m.OriginatorRtrLen {
	case 32:
		originatorBytes = 4
	case 128:
		originatorBytes = 16
	default:
		return nil, fmt.Errorf("invalid originator router length: %d (must be 32 or 128)", m.OriginatorRtrLen)
	}

	if p+originatorBytes > len(b) {
		return nil, fmt.Errorf("truncated originator router address: need %d bytes, have %d", originatorBytes, len(b)-p)
	}

	m.OriginatorRtrAddr = make([]byte, originatorBytes)
	copy(m.OriginatorRtrAddr, b[p:p+originatorBytes])
	p += originatorBytes

	// Parse Reserved (4 bytes)
	if p+4 > len(b) {
		return nil, fmt.Errorf("truncated at reserved field")
	}
	m.Reserved = make([]byte, 4)
	copy(m.Reserved, b[p:p+4])
	p += 4

	// Parse Maximum Response Time (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at maximum response time")
	}
	m.MaxResponseTime = b[p]
	p++

	// Parse Flags (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at flags")
	}
	m.Flags = b[p]
	p++

	// Verify exact length
	if p != len(b) {
		return nil, fmt.Errorf("invalid length of Multicast Leave Synch route: expected %d bytes, have %d", p, len(b))
	}

	return m, nil
}
