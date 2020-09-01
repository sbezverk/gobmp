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
	FlexAlgorithm   uint8               `json:"flex_algo,omitempty"`
	MetricType      uint8               `json:"metric_type,omitempty"`
	CalculationType uint8               `json:"calculation_type,omitempty"`
	Priority        uint8               `json:"priority,omitempty"`
	SubTLV          map[uint16]base.TLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalFlexAlgoDefinition builds Flexible Algorithm Definition (FAD) TLV object
func UnmarshalFlexAlgoDefinition(b []byte) (*FlexAlgoDefinition, error) {
	glog.V(6).Infof("FlexAlgo Definition Raw: %s", tools.MessageHex(b))
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
	tlvs, err := base.UnmarshalTLV(b[p:])
	if err != nil {
		return nil, err
	}
	fad.SubTLV = tlvs

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
	glog.V(6).Infof("FlexAlgo Definition Raw: %s", tools.MessageHex(b))
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
