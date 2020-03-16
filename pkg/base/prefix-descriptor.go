package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
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

// UnmarshalPrefixDescriptor build Prefix Descriptor object
func UnmarshalPrefixDescriptor(b []byte) (*PrefixDescriptor, error) {
	glog.V(6).Infof("PrefixDescriptor Raw: %s", internal.MessageHex(b))
	pd := PrefixDescriptor{}
	p := 0
	ptlv, err := UnmarshalPrefixDescriptorTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	pd.PrefixTLV = ptlv

	return &pd, nil
}
