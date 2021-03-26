package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// IGPFlag defines IGP Flags structure populated from
// https://tools.ietf.org/html/rfc7752#section-3.3.3.1
type IGPFlag struct {
	DFlag bool `json:"d_flag"`
	NFlag bool `json:"n_flag"`
	LFlag bool `json:"l_flag"`
	PFlag bool `json:"p_flag"`
}

// UnmarshalIGPFlag builds IGPFlag Object
func UnmarshalIGPFlags(b []byte) (*IGPFlag, error) {
	if glog.V(6) {
		glog.Infof("IGP Flag TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal")
	}
	f := &IGPFlag{}
	p := 0
	f.DFlag = b[p]&0x80 == 0x80
	f.NFlag = b[p]&0x40 == 0x40
	f.LFlag = b[p]&0x20 == 0x20
	f.PFlag = b[p]&0x10 == 0x10

	return f, nil
}
