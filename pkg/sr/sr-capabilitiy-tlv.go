package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// CapabilityTLV defines SR Capability TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.2
type CapabilityTLV struct {
	Range uint32
	SID   *SIDTLV
}

func (cap *CapabilityTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += tools.AddLevel(l)
	s += "SR Capability TLV:" + "\n"

	return s
}

// MarshalJSON defines a method to Marshal SR Capabilities TLV object into JSON format
func (cap *CapabilityTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"range\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", cap.Range))...)
	jsonData = append(jsonData, []byte("\"sid\":")...)
	jsonData = append(jsonData, tools.RawBytesToJSON(cap.SID.Value)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRCapabilityTLV builds SR Capability TLV object
func UnmarshalSRCapabilityTLV(b []byte) ([]CapabilityTLV, error) {
	glog.V(6).Infof("SR Capability TLV Raw: %s", tools.MessageHex(b))
	caps := make([]CapabilityTLV, 0)
	for p := 0; p < len(b); {
		cap := CapabilityTLV{}
		r := make([]byte, 4)
		// Copy 3 bytes of Range into 4 byte slice to convert it into uint32
		copy(r[1:], b[p:p+3])
		cap.Range = binary.BigEndian.Uint32(r)
		p += 3
		// Getting type of sub tlv
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		v := make([]byte, l)
		copy(v, b[p:p+int(l)])
		p += int(l)
		switch t {
		case 1161:
			// SID Subtlv
			cap.SID = &SIDTLV{
				Type:   t,
				Length: l,
				Value:  v,
			}
		default:
			return nil, fmt.Errorf("unknown SR Capability tlv %d", t)
		}
		caps = append(caps, cap)
	}

	return caps, nil
}
