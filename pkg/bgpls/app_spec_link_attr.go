package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-app-specific-attr-03#section-2

// AppSpecLinkAttr defines a structure of Application Specific Link attributes
type AppSpecLinkAttr struct {
	SAIBMLen  uint8          `json:"saibm_length"`
	UDAIBMLen uint8          `json:"udaibm_length"`
	SAIBM     []byte         `json:"std_app_id_bit_mask,omitempty"`
	UDAIBM    []byte         `json:"ud_app_id_bit_mask,omitempty"`
	SubTLV    []*base.SubTLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalAppSpecLinkAttr builds Application Specific Link Attributes object
func UnmarshalAppSpecLinkAttr(b []byte) (*AppSpecLinkAttr, error) {
	if glog.V(6) {
		glog.Infof("App SpecLink Attr Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("invalid length %d of FlexAlgo definition tlv", len(b))
	}
	asla := AppSpecLinkAttr{
		SubTLV: make([]*base.SubTLV, 0),
	}
	p := 0
	if err := checkBML(b[p]); err != nil {
		return nil, err
	}
	asla.SAIBMLen = b[p]
	p++
	if err := checkBML(b[p]); err != nil {
		return nil, err
	}
	asla.UDAIBMLen = b[p]
	p++
	// Skip reserved bytes
	p += 2
	// Since SAIBM is optional copy only if it exists
	if p+int(asla.SAIBMLen) > len(b) {
		return &asla, nil
	}
	asla.SAIBM = make([]byte, asla.SAIBMLen)
	copy(asla.SAIBM, b[p:p+int(asla.SAIBMLen)])
	p += int(asla.SAIBMLen)
	// Since UDAIBM is optional copy only if it exists
	if p+int(asla.UDAIBMLen) > len(b) {
		return &asla, nil
	}
	asla.UDAIBM = make([]byte, asla.UDAIBMLen)
	copy(asla.UDAIBM, b[p:p+int(asla.UDAIBMLen)])
	p += int(asla.UDAIBMLen)

	if p < len(b) {
		sstlvs, err := base.UnmarshalSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		asla.SubTLV = sstlvs
	}

	return &asla, nil
}

func checkBML(b byte) error {
	switch b {
	case 0:
	case 4:
	case 8:
	default:
		return fmt.Errorf("invalid bit mask length %d", int(b))
	}

	return nil
}
