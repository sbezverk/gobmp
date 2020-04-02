package sr

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocalBlockTLV defines SR Local Block TLV object
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.4
type LocalBlock struct {
	Flags uint8
	TLV   []LocalBlockTLV
}

func (lb *LocalBlock) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += tools.AddLevel(l)
	s += "SR Local Block TLV:" + "\n"
	s += tools.AddLevel(l + 1)
	s += fmt.Sprintf("Flag: %02x\n", lb.Flags)

	return s
}

// MarshalJSON defines a method to Marshal SR Local Block TLV object into JSON format
func (lb *LocalBlock) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"flag\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", lb.Flags))...)
	jsonData = append(jsonData, []byte("\"tlvs\":")...)
	for i, t := range lb.TLV {
		jsonData = append(jsonData, '[')
		b, err := json.Marshal(&t)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		if i < len(lb.TLV)-1 {
			jsonData = append(jsonData, ',')
		}
		jsonData = append(jsonData, ']')
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRLocalBlock builds SR Local Block object
func UnmarshalSRLocalBlock(b []byte) (*LocalBlock, error) {
	glog.V(6).Infof("SR Local BLock Raw: %s", tools.MessageHex(b))
	lb := LocalBlock{}
	p := 0
	lb.Flags = b[p]
	p++
	// Skip reserved byte
	p++
	tlvs, err := UnmarshalSRLocalBlockTLV(b[p:])
	if err != nil {
		return nil, err
	}
	lb.TLV = tlvs

	return &lb, nil
}
