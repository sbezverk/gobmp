package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MultiTopologyIdentifier defines Multi Topology Identifier whcih is alias of uint16
type MultiTopologyIdentifier struct {
	FlagO bool   `json:"flag_o"`
	FlagA bool   `json:"flag_a"`
	MTID  uint16 `json:"mt_id"`
}

// UnmarshalMultiTopologyIdentifierTLV builds Multi Topology Identifier TLV object
func UnmarshalMultiTopologyIdentifierTLV(b []byte) ([]*MultiTopologyIdentifier, error) {
	if glog.V(6) {
		glog.Infof("MultiTopologyIdentifierTLV Raw: %s", tools.MessageHex(b))
	}
	p := 0
	// number of mt_id entries length / 2
	mti := make([]*MultiTopologyIdentifier, len(b)/2)
	for i := 0; i < int(len(b)/2); i++ {
		m := &MultiTopologyIdentifier{}
		d := binary.BigEndian.Uint16(b[p : p+2])
		m.MTID = d & 0x0ffff
		m.FlagO = d&0x8000 == 0x8000
		m.FlagA = d&0x4000 == 0x4000
		mti[i] = m
		p += 2
	}

	return mti, nil
}
