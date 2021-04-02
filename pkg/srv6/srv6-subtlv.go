package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SubTLV defines an interface for SRv6 Sub TLV type
type SubTLV interface {
	GetType() uint16
	GetLen() uint16
}

// List of TLVs and Sub TLVs to process

// +----------+----------------------------------------+
// | TLV Code |             Description                |
// |  Point   |                                        |
// +----------+----------------------------------------+
// |  1038    |   SRv6 Capabilities TLV                |
// |  1106    |   SRv6 End.X SID TLV                   |
// |  1107    |   IS-IS SRv6 LAN End.X SID TLV         |
// |  1108    |   OSPFv3 SRv6 LAN End.X SID TLV        |
// |  1162    |   SRv6 Locator TLV                     |
// |   518    |   SRv6 SID Information TLV             |
// |  1250    |   SRv6 Endpoint Behavior TLV           |
// |  1251    |   SRv6 BGP Peer Node SID TLV           |
// |  1252    |   SRv6 SID Structure TLV               |
// +----------+----------------------------------------+

func UnmarshalSRv6SubTLV(b []byte) (SubTLV, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Sub TLV")
	}
	p := 0
	t := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	l := binary.BigEndian.Uint16(b[p : p+2])
	if p+int(l) < len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Sub TLV")
	}
	if glog.V(6) {
		glog.Infof("SRv6 Sub TLV of type: %d Raw: %s", t, tools.MessageHex(b))
	}
	switch t {
	case 1252:
		return UnmarshalSRv6SIDStructureTLV(b[p : p+int(l)])
	default:
		v := make([]byte, l)
		copy(v, b[p:p+int(l)])
		stlv := &UnknownSrv6SubTLV{
			Type:   t,
			Length: l + 4, // Storing total length 2 bytes of type + 2 bytes of length + length of value
			Value:  v,
		}
		return stlv, nil
	}
}

func UnmarshalAllSRv6SubTLV(b []byte) ([]SubTLV, error) {
	stlvs := make([]SubTLV, 0)
	p := 0
	for p < len(b) {
		stlv, err := UnmarshalSRv6SubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		p += int(stlv.GetLen())
		stlvs = append(stlvs, stlv)
	}
	if len(stlvs) == 0 {
		return nil, nil
	}

	return stlvs, nil
}

type UnknownSrv6SubTLV struct {
	Type   uint16 `json:"type"`
	Length uint16 `json:"length"`
	Value  []byte `json:"value"`
}

func (u *UnknownSrv6SubTLV) GetType() uint16 {
	return u.Type
}
func (u *UnknownSrv6SubTLV) GetLen() uint16 {
	return u.Length
}
