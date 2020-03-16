package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
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

// UnmarshalLinkDescriptor build Link Descriptor object
func UnmarshalLinkDescriptor(b []byte) (*LinkDescriptor, error) {
	glog.V(6).Infof("LinkDescriptor Raw: %s", internal.MessageHex(b))
	ld := LinkDescriptor{}
	p := 0
	ltlv, err := UnmarshalLinkDescriptorTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	ld.LinkTLV = ltlv

	return &ld, nil
}
