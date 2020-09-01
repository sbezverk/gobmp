package bgpls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// FlexAlgoDefinition defines an optional BGP-LS Attribute TLV associated
// with the Node NLRI called the Flexible Algorithm Definition (FAD) TLV
// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-flex-algo-02#section-3
type FlexAlgoDefinition struct {
	FlexAlgorithm   uint8       `json:"flex_algo,omitempty"`
	MetricType      uint8       `json:"metric_type"`
	CalculationType uint8       `json:"calculation_type"`
	Priority        uint8       `json:"priority"`
	SubTLV          []*base.TLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalFlexAlgoDefinition builds Flexible Algorithm Definition (FAD) TLV object
func UnmarshalFlexAlgoDefinition(b []byte) (*FlexAlgoDefinition, error) {
	glog.V(5).Infof("FlexAlgo Definition Raw: %s", tools.MessageHex(b))
	if len(b) < 4 {
		return nil, fmt.Errorf("invalid length %d of FlexAlgo definition tlv", len(b))
	}
	fad := FlexAlgoDefinition{
		SubTLV: make([]*base.TLV, 0),
	}
	p := 0
	fad.FlexAlgorithm = b[p]
	p++
	fad.MetricType = b[p]
	p++
	fad.CalculationType = b[p]
	p++
	fad.Priority = b[p]
	p++
	for p < len(b) {
		stlv := &base.TLV{}
		if p+2 > len(b) {
			break
		}
		stlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+2 > len(b) {
			break
		}
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(stlv.Length) > len(b) {
			break
		}
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		p += int(stlv.Length)
		fad.SubTLV = append(fad.SubTLV, stlv)
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
	glog.V(5).Infof("FlexAlgo Prefix Metric Raw: %s", tools.MessageHex(b))
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
