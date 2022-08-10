package bgpls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// FlexAlgoDefinition defines an optional BGP-LS Attribute TLV associated
// with the Node NLRI called the Flexible Algorithm Definition (FAD) TLV
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-flex-algo-02#section-3
type FlexAlgoDefinition struct {
	FlexAlgorithm   uint8      `json:"flex_algo,omitempty"`
	MetricType      uint8      `json:"metric_type"`
	CalculationType uint8      `json:"calculation_type"`
	Priority        uint8      `json:"priority"`
	SubTLV          *FADSubTLV `json:"sub_tlv,omitempty"`
}

type FADSubTLVFlags struct {
	MFLag bool `json:"m_flag"`
}

type FADSubTLV struct {
	ExcludeAny  []uint32        `json:"exclude_any,omitempty"`
	IncludeAny  []uint32        `json:"include_any,omitempty"`
	IncludeAll  []uint32        `json:"include_all,omitempty"`
	Flags       *FADSubTLVFlags `json:"flags,omitempty"`
	ExcludeSRLG []uint32        `json:"exclude_srlg,omitempty"`
}

func getFADSubTLVValue(tlv *base.SubTLV) ([]uint32, error) {
	if tlv.Length%4 != 0 {
		return nil, fmt.Errorf("invalid length %d of FlexAlgo definition subtlv", tlv.Length)
	}
	count := int(tlv.Length / 4)
	ints := make([]uint32, count)
	for i, p := 0, 0; i < count; i++ {
		ints[i] = binary.BigEndian.Uint32(tlv.Value[p : p+4])
		p += 4
	}
	return ints, nil
}

// UnmarshalFlexAlgoDefinition builds Flexible Algorithm Definition (FAD) TLV object
func UnmarshalFlexAlgoDefinition(b []byte) (*FlexAlgoDefinition, error) {
	if glog.V(6) {
		glog.Infof("FlexAlgo Definition Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("invalid length %d of FlexAlgo definition tlv", len(b))
	}
	fad := FlexAlgoDefinition{}
	p := 0
	fad.FlexAlgorithm = b[p]
	p++
	fad.MetricType = b[p]
	p++
	fad.CalculationType = b[p]
	p++
	fad.Priority = b[p]
	p++
	if p < len(b) {
		sstlvs, err := base.UnmarshalSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		fad.SubTLV = &FADSubTLV{}
		for _, tlv := range sstlvs {
			ints, err := getFADSubTLVValue(tlv)
			if err != nil {
				return nil, err
			}
			switch tlv.Type {
			case 1040:
				fad.SubTLV.ExcludeAny = ints
			case 1041:
				fad.SubTLV.IncludeAny = ints
			case 1042:
				fad.SubTLV.IncludeAll = ints
			case 1043:
				fad.SubTLV.Flags = &FADSubTLVFlags{}
				if tlv.Length < 1 {
					return nil, fmt.Errorf("not enough bytes to decode FlexAlgo definition Sub TLV Flag")
				}
				fad.SubTLV.Flags.MFLag = tlv.Value[0]&0x80 == 0x80
			case 1045: // the type is really TBD in the draft
				fad.SubTLV.ExcludeSRLG = ints
			default:
				return nil, fmt.Errorf("unknown FlexAlgo definition subtlv type %d", tlv.Type)
			}
		}
	}

	return &fad, nil
}

// FlexAlgoPrefixMetric defines an optional BGP-LS Attribute TLV associated
// with the Prefix NLRI called the Flexible Algorithm Prefix Metric
// (FAPM) TLV
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-flex-algo-02#section-4
type FlexAlgoPrefixMetric struct {
	FlexAlgorithm uint8  `json:"flex_algo,omitempty"`
	Metric        uint32 `json:"metric,omitempty"`
}

// UnmarshalFlexAlgoPrefixMetric builds Flexible Algorithm Prefix Metric TLV object
func UnmarshalFlexAlgoPrefixMetric(b []byte) (*FlexAlgoPrefixMetric, error) {
	if glog.V(6) {
		glog.Infof("FlexAlgo Prefix Metric Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 8 {
		return nil, fmt.Errorf("invalid length %d of FlexAlgo prefix metric tlv", len(b))
	}
	fap := FlexAlgoPrefixMetric{}
	p := 0
	fap.FlexAlgorithm = b[p]
	p++
	// Skip
	p += 3
	fap.Metric = binary.BigEndian.Uint32(b[p:])

	return &fap, nil
}
