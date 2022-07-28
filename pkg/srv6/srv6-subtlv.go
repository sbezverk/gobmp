package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
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
// |  1106    |   SRv6 End.X SID TLV                   |   Implemented
// |  1107    |   IS-IS SRv6 LAN End.X SID TLV         |
// |  1108    |   OSPFv3 SRv6 LAN End.X SID TLV        |
// |  1162    |   SRv6 Locator TLV                     |
// |   518    |   SRv6 SID Information TLV             |
// |  1250    |   SRv6 Endpoint Behavior TLV           |
// |  1251    |   SRv6 BGP Peer Node SID TLV           |
// |  1252    |   SRv6 SID Structure TLV               |   Implemented
// +----------+----------------------------------------+

// UnmarshalSRv6SubTLV unmarshals SRv6 Sub TLV based on the type and creates an instance of
// SubTLV interface.
func UnmarshalSRv6SubTLV(b []byte) (SubTLV, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Sub TLV")
	}
	p := 0
	t := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+int(l) > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Sub TLV")
	}
	if glog.V(5) {
		glog.Infof("SRv6 Sub TLV of type: %d Raw: %s", t, tools.MessageHex(b))
	}
	switch t {
	case 1252:
		stlv, err := UnmarshalSRv6SIDStructureTLV(b[p : p+int(l)])
		if err != nil {
			return nil, err
		}
		stlv.Type = t
		stlv.Length = l + 4
		return stlv, nil
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

// UnmarshalAllSRv6SubTLV creates a slice of SubTLV interfaces from a slice of byte.
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

// UnmarshalJSONAllSubTLV creates a slice of SubTLV interfaces from a slice of JSON Raw messages.
func UnmarshalJSONAllSubTLV(stlvs []map[string]json.RawMessage) ([]SubTLV, error) {
	ss := make([]SubTLV, 0)
	for _, stlv := range stlvs {
		var s SubTLV
		v, ok := stlv["type"]
		if !ok {
			return nil, fmt.Errorf("sub-tlv is missing mandatory type field")
		}
		var t uint16
		if err := json.Unmarshal(v, &t); err != nil {
			return nil, err
		}
		v, ok = stlv["length"]
		if !ok {
			return nil, fmt.Errorf("sub-tlv is missing mandatory length field")
		}
		var l uint16
		if err := json.Unmarshal(v, &l); err != nil {
			return nil, err
		}
		var err error
		switch t {
		case 1252:
			s, err = UnmarshalJSONSRv6SIDStructureTLV(stlv)
			if err != nil {
				return nil, err
			}
		default:
			var val []byte
			if v, ok := stlv["value"]; ok {
				if err := json.Unmarshal(v, &val); err != nil {
					return nil, err
				}
			}
			s = &UnknownSrv6SubTLV{
				Type:   t,
				Length: l,
				Value:  val,
			}
		}
		ss = append(ss, s)
	}
	if len(ss) == 0 {
		return nil, nil
	}

	return ss, nil
}

type UnknownSrv6SubTLV struct {
	Type   uint16 `json:"type,omitempty"`
	Length uint16 `json:"length,omitempty"`
	Value  []byte `json:"value,omitempty"`
}

func (u *UnknownSrv6SubTLV) GetType() uint16 {
	return u.Type
}
func (u *UnknownSrv6SubTLV) GetLen() uint16 {
	return u.Length
}
