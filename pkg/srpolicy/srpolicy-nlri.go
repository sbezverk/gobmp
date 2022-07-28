package srpolicy

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// NLRI73MinLen defines minimum size of NLRI 73 (Length 1 byte, Distinguisher 4 bytes, Color 4 bytes and Endpoint 4 or 16 bytes)
	NLRI73MinLen = 13
)

// NLRI73 defines the SR Policy SAFI with codepoint 73.  The AFI
// used MUST be IPv4(1) or IPv6(2).
type NLRI73 struct {
	Length        byte
	Distinguisher uint32
	Color         uint32
	Endpoint      []byte
}

// UnmarshalLSNLRI73 builds Link State NLRI object for SAFI 73
func UnmarshalLSNLRI73(b []byte) (*NLRI73, error) {
	if glog.V(5) {
		glog.Infof("NLRI 73 Raw: %s", tools.MessageHex(b))
	}
	// Minimum size of NLRI 73 is Length 1 byte, Distinguisher 4 bytes, Color 4 bytes and Endpoint 4 or 16 bytes
	if len(b) < NLRI73MinLen {
		return nil, fmt.Errorf("invalid length of byte slice")
	}
	o := &NLRI73{}
	p := 0
	// Storing length in bytes instead of bits
	o.Length = b[p] / 8
	p++
	o.Distinguisher = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	o.Color += binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	switch len(b) - p {
	case 4:
		o.Endpoint = net.IP(b[p:]).To4()
	case 16:
		o.Endpoint = net.IP(b[p:]).To16()
	default:
		return nil, fmt.Errorf("invalid length of byte slice")
	}
	return o, nil
}
