package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SIDNLRI defines Prefix NLRI onject
// Mp RFC yet
type SIDNLRI struct {
	ProtocolID uint8
	Identifier uint64
	LocalNode  *base.NodeDescriptor
	SRv6SID    *SIDDescriptor
}

func (sr *SIDNLRI) String() string {
	var s string
	s += fmt.Sprintf("Protocol ID: %s\n", internal.ProtocolIDString(sr.ProtocolID))
	s += fmt.Sprintf("Identifier: %d\n", sr.Identifier)
	s += sr.LocalNode.String()
	s += sr.SRv6SID.String()

	return s
}

// UnmarshalSRv6SIDNLRI builds SRv6SIDNLRI NLRI object
func UnmarshalSRv6SIDNLRI(b []byte) (*SIDNLRI, error) {
	sr := SIDNLRI{
		SRv6SID: &SIDDescriptor{},
	}
	p := 0
	sr.ProtocolID = b[p]
	p++
	// Skip reserved bytes
	//	p += 3
	sr.Identifier = binary.BigEndian.Uint64(b[p : p+8])
	p += 8
	// Get Node Descriptor's length, skip Node Descriptor Type
	l := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := base.UnmarshalNodeDescriptor(b[p : p+int(l)])
	if err != nil {
		return nil, err
	}
	sr.LocalNode = ln
	// Skip Node Descriptor Type and Length 4 bytes
	p += 4
	p += int(l)
	srd, err := UnmarshalSRv6SIDDescriptor(b[p:len(b)])
	if err != nil {
		return nil, err
	}
	sr.SRv6SID = srd

	return &sr, nil
}
