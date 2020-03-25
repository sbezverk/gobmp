package sr

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// LocalBlockTLV defines SR Local Block TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.4
type LocalBlockTLV struct {
	Flag  uint8
	Range uint32
	SID   []byte
}

func (lb *LocalBlockTLV) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)
	s += "SR Local Block TLV:" + "\n"
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", lb.Flag)

	return s
}

// MarshalJSON defines a method to Marshal SR Local Block TLV object into JSON format
func (lb *LocalBlockTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"flag\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", lb.Flag))...)
	jsonData = append(jsonData, []byte("\"range\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", lb.Range))...)
	jsonData = append(jsonData, []byte("\"sid\":")...)
	jsonData = append(jsonData, internal.RawBytesToJSON(lb.SID)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRLocalBlockTLV builds SR Local Block TLV object
func UnmarshalSRLocalBlockTLV(b []byte) (*LocalBlockTLV, error) {
	glog.V(6).Infof("SR Local BLock TLV Raw: %s", internal.MessageHex(b))
	lb := LocalBlockTLV{}
	p := 0
	lb.Flag = b[0]
	// Ignore reserved byte
	p++
	r := make([]byte, 4)
	// Copy 3 bytes of Range into 4 byte slice to convert it into uint32
	copy(r[1:], b[p:p+3])
	lb.Range = binary.BigEndian.Uint32(r)
	p += 3
	lb.SID = make([]byte, len(b)-p)
	copy(lb.SID, b[p:])

	return &lb, nil
}
