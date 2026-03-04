package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// MultiTopologyIdentifier defines Multi Topology Identifier which is alias of uint16
type MultiTopologyIdentifier struct {
	OFlag bool   `json:"o_flag"`
	AFlag bool   `json:"a_flag"`
	MTID  uint16 `json:"mt_id"`
}

// UnmarshalMultiTopologyIdentifierTLV builds Multi Topology Identifier TLV object
func UnmarshalMultiTopologyIdentifierTLV(b []byte) ([]*MultiTopologyIdentifier, error) {
	if glog.V(6) {
		glog.Infof("MultiTopologyIdentifierTLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("MultiTopologyIdentifierTLV length is 0")
	}
	p := 0
	if len(b)%2 != 0 {
		return nil, fmt.Errorf("MultiTopologyIdentifier: odd-length input %d", len(b))
	}
	// number of mt_id entries length / 2
	mti := make([]*MultiTopologyIdentifier, len(b)/2)
	for i := 0; i < len(b)/2; i++ {
		m := &MultiTopologyIdentifier{}
		d := binary.BigEndian.Uint16(b[p : p+2])
		m.MTID = d & 0x0fff
		m.OFlag = d&0x8000 == 0x8000
		m.AFlag = d&0x4000 == 0x4000
		mti[i] = m
		p += 2
	}

	return mti, nil
}
