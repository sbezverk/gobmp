package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// SMET defines EVPN Type 6 - Selective Multicast Ethernet Tag Route
// RFC 9251 Section 9.1
type SMET struct {
	RD                 *base.RD
	EthTag             []byte // 4 bytes
	McastSrcLen        uint8  // Length in bits: 0, 32, or 128
	McastSrcAddr       []byte // 0, 4, or 16 bytes based on McastSrcLen
	McastGrpLen        uint8  // Length in bits: 32 or 128
	McastGrpAddr       []byte // 4 or 16 bytes based on McastGrpLen
	OriginatorRtrLen   uint8  // Length in bits: 32 or 128
	OriginatorRtrAddr  []byte // 4 or 16 bytes based on OriginatorRtrLen
	Flags              uint8  // Flags byte
}

// GetRouteTypeSpec returns the route type spec object
func (s *SMET) GetRouteTypeSpec() interface{} {
	return s
}

// getRD returns Route Distinguisher as a string
func (s *SMET) getRD() string {
	return s.RD.String()
}

// getESI returns nil as Type 6 does not have ESI
func (s *SMET) getESI() *ESI {
	return nil
}

// getTag returns Ethernet Tag ID
func (s *SMET) getTag() []byte {
	return s.EthTag
}

// getMAC returns nil as Type 6 does not have MAC
func (s *SMET) getMAC() *MACAddress {
	return nil
}

// getMACLength returns nil as Type 6 does not have MAC
func (s *SMET) getMACLength() *uint8 {
	return nil
}

// getIPAddress returns nil as Type 6 does not have IP address
func (s *SMET) getIPAddress() []byte {
	return nil
}

// getIPLength returns nil as Type 6 does not have IP length
func (s *SMET) getIPLength() *uint8 {
	return nil
}

// getGWAddress returns nil as Type 6 does not have gateway address
func (s *SMET) getGWAddress() []byte {
	return nil
}

// getLabel returns nil as Type 6 does not have labels
func (s *SMET) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNSMET parses EVPN Type 6 SMET Route from wire format
// RFC 9251 Section 9.1
func UnmarshalEVPNSMET(b []byte) (*SMET, error) {
	// Check minimum fields: RD(8) + EthTag(4) + McastSrcLen(1) = 13 bytes
	if len(b) < 13 {
		return nil, fmt.Errorf("invalid length of SMET route: need at least 13 bytes, have %d", len(b))
	}

	s := &SMET{}
	p := 0

	// Parse RD (8 bytes)
	if p+8 > len(b) {
		return nil, fmt.Errorf("truncated at RD")
	}
	rd, err := base.MakeRD(b[p : p+8])
	if err != nil {
		return nil, fmt.Errorf("failed to parse RD: %w", err)
	}
	s.RD = rd
	p += 8

	// Parse Ethernet Tag ID (4 bytes)
	if p+4 > len(b) {
		return nil, fmt.Errorf("truncated at ethernet tag")
	}
	s.EthTag = make([]byte, 4)
	copy(s.EthTag, b[p:p+4])
	p += 4

	// Parse Multicast Source Length (1 byte)
	s.McastSrcLen = b[p]
	p++

	// Validate and parse Multicast Source Address
	var mcastSrcBytes int
	switch s.McastSrcLen {
	case 0:
		mcastSrcBytes = 0
	case 32:
		mcastSrcBytes = 4
	case 128:
		mcastSrcBytes = 16
	default:
		return nil, fmt.Errorf("invalid multicast source length: %d (must be 0, 32, or 128)", s.McastSrcLen)
	}

	if p+mcastSrcBytes > len(b) {
		return nil, fmt.Errorf("truncated multicast source address: need %d bytes, have %d", mcastSrcBytes, len(b)-p)
	}

	if mcastSrcBytes > 0 {
		s.McastSrcAddr = make([]byte, mcastSrcBytes)
		copy(s.McastSrcAddr, b[p:p+mcastSrcBytes])
		p += mcastSrcBytes
	}

	// Parse Multicast Group Length (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at multicast group length")
	}
	s.McastGrpLen = b[p]
	p++

	// Validate and parse Multicast Group Address
	var mcastGrpBytes int
	switch s.McastGrpLen {
	case 32:
		mcastGrpBytes = 4
	case 128:
		mcastGrpBytes = 16
	default:
		return nil, fmt.Errorf("invalid multicast group length: %d (must be 32 or 128)", s.McastGrpLen)
	}

	if p+mcastGrpBytes > len(b) {
		return nil, fmt.Errorf("truncated multicast group address: need %d bytes, have %d", mcastGrpBytes, len(b)-p)
	}

	s.McastGrpAddr = make([]byte, mcastGrpBytes)
	copy(s.McastGrpAddr, b[p:p+mcastGrpBytes])
	p += mcastGrpBytes

	// Parse Originator Router Length (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at originator router length")
	}
	s.OriginatorRtrLen = b[p]
	p++

	// Validate and parse Originator Router Address
	var originatorBytes int
	switch s.OriginatorRtrLen {
	case 32:
		originatorBytes = 4
	case 128:
		originatorBytes = 16
	default:
		return nil, fmt.Errorf("invalid originator router length: %d (must be 32 or 128)", s.OriginatorRtrLen)
	}

	if p+originatorBytes > len(b) {
		return nil, fmt.Errorf("truncated originator router address: need %d bytes, have %d", originatorBytes, len(b)-p)
	}

	s.OriginatorRtrAddr = make([]byte, originatorBytes)
	copy(s.OriginatorRtrAddr, b[p:p+originatorBytes])
	p += originatorBytes

	// Parse Flags (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at flags")
	}
	s.Flags = b[p]
	p++

	// Verify exact length
	if p != len(b) {
		return nil, fmt.Errorf("invalid length of SMET route: expected %d bytes, have %d", p, len(b))
	}

	return s, nil
}
