package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// IGPFlags defines IGP Flags structure populated from
// https://tools.ietf.org/html/rfc7752#section-3.3.3.1
type IGPFlags struct {
	DFlag bool `json:"d_flag"`
	NFlag bool `json:"n_flag"`
	LFlag bool `json:"l_flag"`
	PFlag bool `json:"p_flag"`
}

// UnmarshalIGPFlag builds IGPFlag Object
func UnmarshalIGPFlags(b []byte) (*IGPFlags, error) {
	if glog.V(6) {
		glog.Infof("IGP Flags TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal")
	}
	f := &IGPFlags{}
	p := 0
	f.DFlag = b[p]&0x01 == 0x01
	f.NFlag = b[p]&0x02 == 0x02
	f.LFlag = b[p]&0x04 == 0x04
	f.PFlag = b[p]&0x08 == 0x08

	return f, nil
}
