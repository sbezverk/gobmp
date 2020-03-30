package base

import (
	"encoding/binary"
	"fmt"

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

func (mti *MultiTopologyIdentifierTLV) String() string {
	var s string
	s += "   Multi-Topology Identifiers:" + "\n"
	for _, id := range mti.MTI {
		s += fmt.Sprintf("      Identifier: %d\n", 0x0fff&id)
	}
	return s
}

// MarshalJSON defines a method to Marshal slice of Multi Topology Identifier TLVs into JSON format
func (mti *MultiTopologyIdentifierTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '[')
	for i, mid := range mti.MTI {
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d", mid))...)
		if i < len(mti.MTI)-1 {
			jsonData = append(jsonData, ',')
		}
	}

	jsonData = append(jsonData, ']')

	return jsonData, nil
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
