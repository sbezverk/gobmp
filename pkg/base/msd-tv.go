package base

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// MSDTV defines MSD Type Value tuple
type MSDTV struct {
	Type  uint8 `json:"msd_type"`
	Value uint8 `json:"msd_value"`
}

// UnmarshalMSDTV builds slice of MSD Type Value tuples
func UnmarshalMSDTV(b []byte) ([]*MSDTV, error) {
	if glog.V(6) {
		glog.Infof("UnmarshalMSDTV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 1 || len(b)%2 != 0 {
		return nil, fmt.Errorf("invalid MSDTV length: %d", len(b))
	}
	tvs := make([]*MSDTV, 0)
	for p := 0; p < len(b); {
		tv := &MSDTV{}
		tv.Type = b[p]
		p++
		tv.Value = b[p]
		p++
		tvs = append(tvs, tv)
	}

	return tvs, nil
}
