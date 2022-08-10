package srv6

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// SIDStructure defines SRv6 SID Structure TLV object
// No RFC yet
type SIDStructure struct {
	Type      uint16 `json:"type,omitempty"`
	Length    uint16 `json:"length,omitempty"`
	LBLength  uint8  `json:"locator_block_length"`
	LNLength  uint8  `json:"locator_node_length"`
	FunLength uint8  `json:"function_length"`
	ArgLength uint8  `json:"argument_length"`
}

func (s *SIDStructure) GetType() uint16 {
	return s.Type
}

func (s *SIDStructure) GetLen() uint16 {
	return s.Length
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

func UnmarshalJSONSRv6SIDStructureTLV(stlv map[string]json.RawMessage) (*SIDStructure, error) {
	result := &SIDStructure{}
	// Type      uint16 `json:"type,omitempty"`
	if v, ok := stlv["type"]; ok {
		if err := json.Unmarshal(v, &result.Type); err != nil {
			return nil, err
		}
	}
	// Length    uint16 `json:"length,omitempty"`
	if v, ok := stlv["length"]; ok {
		if err := json.Unmarshal(v, &result.Length); err != nil {
			return nil, err
		}
	}
	// LBLength  uint8  `json:"locator_block_length"`
	if v, ok := stlv["locator_block_length"]; ok {
		if err := json.Unmarshal(v, &result.LBLength); err != nil {
			return nil, err
		}
	}
	// LNLength  uint8  `json:"locator_node_length"`
	if v, ok := stlv["locator_node_length"]; ok {
		if err := json.Unmarshal(v, &result.LNLength); err != nil {
			return nil, err
		}
	}
	// FunLength uint8  `json:"function_length"`
	if v, ok := stlv["function_length"]; ok {
		if err := json.Unmarshal(v, &result.FunLength); err != nil {
			return nil, err
		}
	}
	// ArgLength uint8  `json:"argument_length"`
	if v, ok := stlv["argument_length"]; ok {
		if err := json.Unmarshal(v, &result.ArgLength); err != nil {
			return nil, err
		}
	}

	return result, nil
}
