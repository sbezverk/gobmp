package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MSDTV defines MSD Type Value tuple
type MSDTV struct {
	Type  uint8
	Value uint8
}

// UnmarshalMSDTV builds slice of MSD Type Value tuples
func UnmarshalMSDTV(b []byte) ([]MSDTV, error) {
	glog.V(6).Infof("UnmarshalMSDTV Raw: %s", tools.MessageHex(b))
	tvs := make([]MSDTV, 0)
	for p := 0; p < len(b); {
		tv := MSDTV{}
		tv.Type = b[p]
		p++
		tv.Value = b[p]
		p++
		tvs = append(tvs, tv)
	}

	return tvs, nil
}
