package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MultiTopologyIdentifier defines Multi Topology Identifier whcih is alias of uint16
type MultiTopologyIdentifier uint16

// MultiTopologyIdentifierTLV defines Multi Topology Identifier TLV object
// RFC7752
type MultiTopologyIdentifierTLV struct {
	MTI []MultiTopologyIdentifier
}

// GetMTID returns a slice of MTI found in Multi Topology Identifier object
func (mti *MultiTopologyIdentifierTLV) GetMTID() []uint16 {
	mtis := make([]uint16, 0)
	for _, m := range mti.MTI {
		mtis = append(mtis, uint16(m))
	}
	return mtis
}

// UnmarshalMultiTopologyIdentifierTLV builds Multi Topology Identifier TLV object
func UnmarshalMultiTopologyIdentifierTLV(b []byte) (*MultiTopologyIdentifierTLV, error) {
	glog.V(6).Infof("MultiTopologyIdentifierTLV Raw: %s", tools.MessageHex(b))
	mti := MultiTopologyIdentifierTLV{
		MTI: make([]MultiTopologyIdentifier, 0),
	}
	for p := 0; p < len(b); {
		mti.MTI = append(mti.MTI, MultiTopologyIdentifier(binary.BigEndian.Uint16(b[p:p+2])))
		p += 2
	}

	return &mti, nil
}
