package evpn

import (
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// SPMSI defines EVPN Type 10 - S-PMSI A-D Route
// RFC 9572 Section 3.2
type SPMSI struct {
	RD             *base.RD
	EthTag         []byte // 4 bytes
	McastSrcLen    uint8  // Length in bits: 0, 32, or 128
	McastSrcAddr   []byte // 0, 4, or 16 bytes based on McastSrcLen
	McastGrpLen    uint8  // Length in bits: 32 or 128
	McastGrpAddr   []byte // 4 or 16 bytes based on McastGrpLen
	OriginatorLen  uint8  // Length in bits: 32 or 128
	OriginatorAddr []byte // 4 or 16 bytes based on OriginatorLen
}

// GetRouteTypeSpec returns the route type spec object
func (s *SPMSI) GetRouteTypeSpec() interface{} {
	return s
}

// getRD returns Route Distinguisher as a string
func (s *SPMSI) getRD() string {
	return s.RD.String()
}

// getESI returns nil as Type 10 does not have ESI
func (s *SPMSI) getESI() *ESI {
	return nil
}

// getTag returns Ethernet Tag ID
func (s *SPMSI) getTag() []byte {
	return s.EthTag
}

// getMAC returns nil as Type 10 does not have MAC
func (s *SPMSI) getMAC() *MACAddress {
	return nil
}

// getMACLength returns nil as Type 10 does not have MAC
func (s *SPMSI) getMACLength() *uint8 {
	return nil
}

// getIPAddress returns nil as Type 10 does not have IP address
func (s *SPMSI) getIPAddress() []byte {
	return nil
}

// getIPLength returns nil as Type 10 does not have IP length
func (s *SPMSI) getIPLength() *uint8 {
	return nil
}

// getGWAddress returns nil as Type 10 does not have gateway address
func (s *SPMSI) getGWAddress() []byte {
	return nil
}

// getLabel returns nil as Type 10 does not have labels
func (s *SPMSI) getLabel() []*base.Label {
	return nil
}

// UnmarshalEVPNSPMSI parses EVPN Type 10 S-PMSI A-D Route from wire format
// RFC 9572 Section 3.2
func UnmarshalEVPNSPMSI(b []byte) (*SPMSI, error) {
	// Minimum S-PMSI A-D length:
	// RD(8) + EthTag(4) + McastSrcLen(1) + McastGrpLen(1) + McastGrpAddr(4) +
	// OriginatorLen(1) + OriginatorAddr(4) = 23 bytes
	if len(b) < 23 {
		return nil, fmt.Errorf("invalid length of S-PMSI A-D route: need at least 23 bytes, have %d", len(b))
	}

	s := &SPMSI{}
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

	// Parse Originator Address Length (1 byte)
	if p >= len(b) {
		return nil, fmt.Errorf("truncated at originator address length")
	}
	s.OriginatorLen = b[p]
	p++

	// Validate and parse Originator Address
	var originatorBytes int
	switch s.OriginatorLen {
	case 32:
		originatorBytes = 4
	case 128:
		originatorBytes = 16
	default:
		return nil, fmt.Errorf("invalid originator address length: %d (must be 32 or 128)", s.OriginatorLen)
	}

	if p+originatorBytes > len(b) {
		return nil, fmt.Errorf("truncated originator address: need %d bytes, have %d", originatorBytes, len(b)-p)
	}

	s.OriginatorAddr = make([]byte, originatorBytes)
	copy(s.OriginatorAddr, b[p:p+originatorBytes])
	p += originatorBytes

	// Verify exact length
	if p != len(b) {
		return nil, fmt.Errorf("invalid length of S-PMSI A-D route: expected %d bytes, have %d", p, len(b))
	}

	return s, nil
}
