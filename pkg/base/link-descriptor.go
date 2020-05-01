package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkDescriptor defines Link Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptor struct {
	LinkTLV map[uint16]TLV
}

// UnmarshalLinkDescriptor build Link Descriptor object
func UnmarshalLinkDescriptor(b []byte) (*LinkDescriptor, error) {
	glog.V(6).Infof("LinkDescriptor Raw: %s", tools.MessageHex(b))
	ld := LinkDescriptor{}
	p := 0
	ltlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	ld.LinkTLV = ltlv

	return &ld, nil
}
