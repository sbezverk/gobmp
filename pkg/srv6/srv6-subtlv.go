package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SubTLV defines SRv6 Sub TLV object
// No RFC yet
type SubTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (stlv *SubTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)

	return s
}

// MarshalJSON defines a method to Marshal SRv6 Sub TLV object into JSON format
func (stlv *SubTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	switch stlv.Type {
	case 1252:
		jsonData = append(jsonData, []byte("\"srv6SIDStructure\":")...)
		st, err := UnmarshalSRv6SIDStructureTLV(stlv.Value)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(st)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	default:
		jsonData = append(jsonData, []byte("\"type\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", stlv.Type))...)
		jsonData = append(jsonData, []byte("\"length\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", stlv.Length))...)
		jsonData = append(jsonData, []byte("\"value\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(stlv.Value)...)
	}

	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRv6SubTLV builds a collection of SRv6 Sub TLV
func UnmarshalSRv6SubTLV(b []byte) ([]SubTLV, error) {
	glog.V(6).Infof("SRv6 Sub TLV Raw: %s", internal.MessageHex(b))
	stlvs := make([]SubTLV, 0)
	for p := 0; p < len(b); {
		stlv := SubTLV{}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		p += int(stlv.Length)
		stlvs = append(stlvs, stlv)
	}

	return stlvs, nil
}
