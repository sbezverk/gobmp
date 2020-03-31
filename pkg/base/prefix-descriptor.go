package base

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixDescriptor defines Prefix Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.3
type PrefixDescriptor struct {
	PrefixTLV []PrefixDescriptorTLV
}

func (pd *PrefixDescriptor) String() string {
	var s string
	s += "Prefix Descriptor TLVs:" + "\n"
	for _, stlv := range pd.PrefixTLV {
		s += stlv.String()
	}

	return s
}

// MarshalJSON defines a method to Marshal Prefix Descriptor object into JSON format
func (pd *PrefixDescriptor) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"PrefixTLV\":")...)
	jsonData = append(jsonData, '[')
	if pd.PrefixTLV != nil {
		for i, tlv := range pd.PrefixTLV {
			b, err := json.Marshal(&tlv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(pd.PrefixTLV)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalPrefixDescriptor build Prefix Descriptor object
func UnmarshalPrefixDescriptor(b []byte) (*PrefixDescriptor, error) {
	glog.V(6).Infof("PrefixDescriptor Raw: %s", tools.MessageHex(b))
	pd := PrefixDescriptor{}
	p := 0
	ptlv, err := UnmarshalPrefixDescriptorTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	pd.PrefixTLV = ptlv

	return &pd, nil
}
