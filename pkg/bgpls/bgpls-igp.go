package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// IGPFlags defines IGP Flags structure populated from
// https://www.rfc-editor.org/rfc/rfc9552#section-5.3.3.1
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
		return nil, fmt.Errorf("not enough bytes to unmarshal IGP Flags: need at least 1 byte, have %d", len(b))
	}
	f := &IGPFlags{}
	p := 0
	// RFC 9552 §5.3.3.1: |D|N|L|P|Reserved|, bit 0 is the most significant.
	f.DFlag = b[p]&0x80 == 0x80
	f.NFlag = b[p]&0x40 == 0x40
	f.LFlag = b[p]&0x20 == 0x20
	f.PFlag = b[p]&0x10 == 0x10

	return f, nil
}
