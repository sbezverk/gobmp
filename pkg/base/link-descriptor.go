package base

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkDescriptor defines Link Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptor struct {
	LinkTLV []LinkDescriptorTLV
}

func (ld *LinkDescriptor) String() string {
	var s string
	s += "Link Desriptor TLVs:" + "\n"
	for _, stlv := range ld.LinkTLV {
		s += stlv.String()
	}

	return s
}

// MarshalJSON defines a method to Marshal Link Descriptor object into JSON format
func (ld *LinkDescriptor) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"LinkTLV\":")...)
	jsonData = append(jsonData, '[')
	if ld.LinkTLV != nil {
		for i, tlv := range ld.LinkTLV {
			b, err := json.Marshal(&tlv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(ld.LinkTLV)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalLinkDescriptor build Link Descriptor object
func UnmarshalLinkDescriptor(b []byte) (*LinkDescriptor, error) {
	glog.V(6).Infof("LinkDescriptor Raw: %s", tools.MessageHex(b))
	ld := LinkDescriptor{}
	p := 0
	ltlv, err := UnmarshalLinkDescriptorTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	ld.LinkTLV = ltlv

	return &ld, nil
}
