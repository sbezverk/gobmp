package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// CapabilitySubTLV defines SR Capability TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.2
type CapabilitySubTLV struct {
	Range uint32 `json:"range,omitempty"`
	SID   uint32 `json:"sid,omitempty"`
}

// UnmarshalSRCapabilitySubTLV builds SR Capability TLV object
func UnmarshalSRCapabilitySubTLV(b []byte) ([]CapabilitySubTLV, error) {
	if glog.V(6) {
		glog.Infof("SR Capability TLV Raw: %s", tools.MessageHex(b))
	}
	caps := make([]CapabilitySubTLV, 0)
	for p := 0; p < len(b); {
		cap := CapabilitySubTLV{}
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
		switch t {
		// Sanity check for supported Capability Sub TLV types
		case 1161:
		default:
			return nil, fmt.Errorf("unknown SR Capability tlv type %d", t)
		}
		s := make([]byte, 4)
		switch l {
		case 3:
			copy(s[1:], b[p:p+int(l)])
		case 4:
			copy(s, b[p:p+int(l)])
		default:
			return nil, fmt.Errorf("invalid length %d for Prefix SID TLV", len(b))
		}
		cap.SID = binary.BigEndian.Uint32(s)
		p += int(l)
		caps = append(caps, cap)
	}

	return caps, nil
}
