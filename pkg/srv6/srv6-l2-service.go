package srv6

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// L2Service defines SRv6 L2 Service message structure
// https://www.rfc-editor.org/rfc/rfc9252#section-4
type L2Service struct {
	SubTLVs map[uint8][]SvcSubTLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalJSON unmarshals a slice of byte into L2Service object
func (l2s *L2Service) UnmarshalJSON(b []byte) error {
	l2s.SubTLVs = make(map[uint8][]SvcSubTLV)
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	var subtlvs map[string]json.RawMessage
	if err := json.Unmarshal(objmap["sub_tlvs"], &subtlvs); err != nil {
		return err
	}
	for subtlvType, subtlvValue := range subtlvs {
		t, err := strconv.Atoi(subtlvType)
		if err != nil {
			return err
		}
		stlvs, ok := l2s.SubTLVs[uint8(t)]
		if !ok {
			l2s.SubTLVs[uint8(t)] = make([]SvcSubTLV, 0)
		}
		switch t {
		case 1:
			istlvs := make([]*InformationSubTLV, 0)
			if err := json.Unmarshal(subtlvValue, &istlvs); err != nil {
				return err
			}
			for _, e := range istlvs {
				var s SvcSubTLV = e
				stlvs = append(stlvs, s)
			}
		default:
			return fmt.Errorf("unknown SRv6 L2 Service Sub TLV type %d", t)
		}
		l2s.SubTLVs[uint8(t)] = stlvs
	}

	return nil
}

// UnmarshalSRv6L2Service instantiates from the slice of bytes an SRv6 L2 Service Object
func UnmarshalSRv6L2Service(b []byte) (*L2Service, error) {
	if glog.V(6) {
		glog.Infof("SRv6 L2 Service Raw: %s", tools.MessageHex(b))
	}
	l2 := L2Service{
		SubTLVs: make(map[uint8][]SvcSubTLV),
	}
	// Skipping reserved byte
	stlv, err := UnmarshalSRv6L3ServiceSubTLV(b[1:])
	if err != nil {
		return nil, err
	}
	l2.SubTLVs = stlv

	return &l2, nil
}
