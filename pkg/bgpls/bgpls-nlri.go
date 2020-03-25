package bgpls

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// NLRI defines BGP-LS NLRI object as collection of BGP-LS TLVs
// https://tools.ietf.org/html/rfc7752#section-3.3
type NLRI struct {
	LS []TLV
}

func (ls *NLRI) String() string {
	var s string

	s += "BGP-LS TLVs:" + "\n"
	for _, tlv := range ls.LS {
		s += tlv.String()
	}

	return s
}

// MarshalJSON defines a method to  BGP-LS TLV object into JSON format
func (ls *NLRI) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"BGPLSTLV\":")...)
	jsonData = append(jsonData, '[')
	if ls.LS != nil {
		for i, tlv := range ls.LS {
			b, err := json.Marshal(&tlv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(ls.LS)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPLSNLRI builds Prefix NLRI object
func UnmarshalBGPLSNLRI(b []byte) (*NLRI, error) {
	glog.V(6).Infof("BGPLSNLRI Raw: %s", internal.MessageHex(b))
	bgpls := NLRI{}
	ls, err := UnmarshalBGPLSTLV(b)
	if err != nil {
		return nil, err
	}
	bgpls.LS = ls

	return &bgpls, nil
}
