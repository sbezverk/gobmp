package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocalBlockTLV defines Local Block TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.4
type LocalBlockTLV struct {
	SubRange uint32
	SID      *SIDTLV
}

// UnmarshalSRLocalBlockTLV builds SR LocalBlock TLV object
func UnmarshalSRLocalBlockTLV(b []byte) ([]LocalBlockTLV, error) {
	glog.V(6).Infof("SR LocalBlock TLV Raw: %s", tools.MessageHex(b))
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
		v := make([]byte, l)
		copy(v, b[p:p+int(l)])
		p += int(l)
		switch t {
		case 1161:
			// SID Subtlv
			tlv.SID = &SIDTLV{
				Type:   t,
				Length: l,
				Value:  v,
			}
		default:
			return nil, fmt.Errorf("unknown SR LocalBLock tlv %d", t)
		}
		tlvs = append(tlvs, tlv)
	}

	return tlvs, nil
}
