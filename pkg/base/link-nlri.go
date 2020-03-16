package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// LinkNLRI defines Node NLRI onject
// https://tools.ietf.org/html/rfc7752#section-3.2
type LinkNLRI struct {
	ProtocolID uint8
	//	Reserved   [3]byte
	Identifier uint64
	LocalNode  *NodeDescriptor
	RemoteNode *NodeDescriptor
	Link       *LinkDescriptor
}

func (l *LinkNLRI) String() string {
	var s string
	s += fmt.Sprintf("Protocol ID: %s\n", internal.ProtocolIDString(l.ProtocolID))
	s += fmt.Sprintf("Identifier: %d\n", l.Identifier)
	s += l.LocalNode.String()
	s += l.RemoteNode.String()
	s += l.Link.String()

	return s
}

// UnmarshalLinkNLRI builds Link NLRI object
func UnmarshalLinkNLRI(b []byte) (*LinkNLRI, error) {
	glog.V(6).Infof("LinkNLRI Raw: %s", internal.MessageHex(b))
	l := LinkNLRI{}
	p := 0
	l.ProtocolID = b[p]
	p++
	// Skip 3 reserved bytes
	//	p += 3
	l.Identifier = binary.BigEndian.Uint64(b[p : p+8])
	p += 8
	// Local Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	l.LocalNode = ln
	// Skip Node Type and Length 4 bytes
	p += 4
	p += int(ndl)
	// Remote Node Descriptor
	// Get Node Descriptor's length, skip Node Descriptor Type
	ndl = binary.BigEndian.Uint16(b[p+2 : p+4])
	rn, err := UnmarshalNodeDescriptor(b[p : p+int(ndl)])
	if err != nil {
		return nil, err
	}
	l.RemoteNode = rn
	p += int(ndl)
	// Skip Node Type and Length 4 bytes
	p += 4
	// Link Descriptor
	ld, err := UnmarshalLinkDescriptor(b[p:len(b)])
	if err != nil {
		return nil, err
	}
	l.Link = ld

	return &l, nil
}
