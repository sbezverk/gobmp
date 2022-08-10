package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// LocalBlockTLV defines Local Block TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.4
type LocalBlockTLV struct {
	SubRange uint32  `json:"range_size,omitempty"`
	Label    *uint32 `json:"label,omitempty"`
	Index    *uint32 `json:"index,omitempty"`
}

// UnmarshalSRLocalBlockTLV builds SR LocalBlock TLV object
func UnmarshalSRLocalBlockTLV(b []byte) ([]LocalBlockTLV, error) {
	if glog.V(6) {
		glog.Infof("SR LocalBlock TLV Raw: %s", tools.MessageHex(b))
	}
	tlvs := make([]LocalBlockTLV, 0)
	for p := 0; p < len(b); {
		tlv := LocalBlockTLV{}
		r := make([]byte, 4)
		// Copy 3 bytes of Range into 4 byte slice to convert it into uint32
		copy(r[1:], b[p:p+3])
		tlv.SubRange = binary.BigEndian.Uint32(r)
		p += 3
		// Getting type of sub tlv
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		v := make([]byte, 4)
		if l == 3 {
			copy(v[1:], b[p:p+int(l)])
		} else {
			copy(v, b[p:p+int(l)])
		}
		s := binary.BigEndian.Uint32(v)
		p += int(l)
		switch t {
		case 1161:
			// SID Subtlv
			switch l {
			case 3:
				// Length 3 indicates a label, only 20 rightmost bits are used
				s &= 0x000fffff
				tlv.Label = &s
			case 4:
				// Length 4 indicates an index
				tlv.Index = &s
			}
		default:
			return nil, fmt.Errorf("unknown SR LocalBLock tlv %d", t)
		}
		tlvs = append(tlvs, tlv)
	}

	return tlvs, nil
}
