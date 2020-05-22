package srv6

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// EndXSIDTLV defines SRv6 End.X SID TLV object
// No RFC yet
type EndXSIDTLV struct {
	EndpointBehavior uint16              `json:"endpoint_behavior,omitempty"`
	BFlag            bool                `json:"b_flag"`
	SFlag            bool                `json:"s_flag"`
	PFlag            bool                `json:"p_flag"`
	Algorithm        uint8               `json:"algorithm,omitempty"`
	Weight           uint8               `json:"weight,omitempty"`
	SID              string              `json:"sid,omitempty"`
	SubTLVs          map[uint16]base.TLV `json:"sub_tlvs,omitempty"`
}

const (
	// EndXSIDTLVMinLen defines minimum valid length of End.X SID TLV
	EndXSIDTLVMinLen = 22
)

// UnmarshalSRv6EndXSIDTLV builds SRv6 End.X SID TLV object
func UnmarshalSRv6EndXSIDTLV(b []byte) (*EndXSIDTLV, error) {
	glog.V(6).Infof("SRv6 End.X SID TLV Raw: %s", tools.MessageHex(b))
	if len(b) < EndXSIDTLVMinLen {
		return nil, fmt.Errorf("invalid length of data %d, expected minimum of %d", len(b), EndXSIDTLVMinLen)
	}
	endx := EndXSIDTLV{}
	p := 0
	endx.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	endx.BFlag = b[p]&0x01 == 0x01
	endx.SFlag = b[p]&0x02 == 0x02
	endx.PFlag = b[p]&0x04 == 0x04
	p++
	endx.Algorithm = b[p]
	p++
	endx.Weight = b[p]
	p++
	// Skip reserved byte
	p++
	sid := net.IP(b[p : p+16])
	if sid.To16() == nil {
		return nil, fmt.Errorf("invalid sid format")
	}
	endx.SID = sid.To16().String()
	p += 16
	if len(b) > p {
		stlvs, err := base.UnmarshalTLV(b[p:])
		if err != nil {
			return nil, err
		}
		endx.SubTLVs = stlvs
	}

	return &endx, nil
}
