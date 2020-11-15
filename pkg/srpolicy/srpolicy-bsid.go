package srpolicy

import (
	"encoding/binary"

	"github.com/sbezverk/gobmp/pkg/srv6"
)

// BSIDType defines type of BSID value
type BSIDType int

const (
	// NOBSID subtlv does not carry BSID
	NOBSID BSIDType = iota
	// LABELBSID subtlv carries Label as BSID
	LABELBSID
	// SRV6BSID subtlv carries SRv6 as BSID
	SRV6BSID
)

// BSID defines methods to get type and value of different types of Binding SID
type BSID interface {
	GetFlag() byte
	GetType() BSIDType
	GetBSID() []byte
}

// noBSID defines structure when Binding SID sub tlv carries no SID
type noBSID struct {
	flags byte
}

func (n *noBSID) GetFlag() byte {
	return n.flags
}
func (n *noBSID) GetType() BSIDType {
	return NOBSID
}
func (n *noBSID) GetBSID() []byte {
	return nil
}

// labelBSID defines structure when Binding SID sub tlv carries a label as Binding SID
type labelBSID struct {
	flags byte
	bsid  uint32
}

func (l *labelBSID) GetFlag() byte {
	return l.flags
}
func (l *labelBSID) GetType() BSIDType {
	return LABELBSID
}
func (l *labelBSID) GetBSID() []byte {
	bsid := make([]byte, 4)
	binary.BigEndian.PutUint32(bsid, l.bsid)
	return bsid
}

// SRv6BSID defines SRv6 BSID specific method
type SRv6BSID interface {
	GetEndpointBehavior() *srv6.EndpointBehavior
}

// srv6BSID defines structure when Binding SID sub tlv carries a srv6 as Binding SID
type srv6BSID struct {
	flag byte
	bsid []byte
	eb   *srv6.EndpointBehavior
}

func (s *srv6BSID) GetFlag() byte {
	return s.flag
}
func (s *srv6BSID) GetType() BSIDType {
	return SRV6BSID
}
func (s *srv6BSID) GetBSID() []byte {
	return s.bsid
}
func (s *srv6BSID) GetEndpointBehavior() *srv6.EndpointBehavior {
	return s.eb
}
