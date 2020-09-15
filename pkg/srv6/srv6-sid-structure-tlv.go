package srv6

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SIDStructure defines SRv6 SID Structure TLV object
// No RFC yet
type SIDStructure struct {
	LBLength  uint8 `json:"locator_block_length"`
	LNLength  uint8 `json:"locator_node_length"`
	FunLength uint8 `json:"function_length"`
	ArgLength uint8 `json:"argument_length"`
}

// UnmarshalSRv6SIDStructureTLV builds SRv6 SID Structure TLV object
func UnmarshalSRv6SIDStructureTLV(b []byte) (*SIDStructure, error) {
	if glog.V(6) {
		glog.Infof("SRv6 SID Structure TLV Raw: %s", tools.MessageHex(b))
	}
	st := SIDStructure{}
	p := 0
	st.LBLength = b[p]
	p++
	st.LNLength = b[p]
	p++
	st.FunLength = b[p]
	p++
	st.ArgLength = b[p]

	return &st, nil
}
