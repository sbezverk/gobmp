package bgpls

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// NodeFlags defines Node Attribute Flags TLV
// https://tools.ietf.org/html/rfc7752#section-3.3.1.1
// +-----------------+-------------------------+------------+
// |       Bit       | Description             | Reference  |
// +-----------------+-------------------------+------------+
// |       'O'       | Overload Bit            | [ISO10589] |
// |       'T'       | Attached Bit            | [ISO10589] |
// |       'E'       | External Bit            | [RFC2328]  |
// |       'B'       | ABR Bit                 | [RFC2328]  |
// |       'R'       | Router Bit              | [RFC5340]  |
// |       'V'       | V6 Bit                  | [RFC5340]  |
// +-----------------+-------------------------+------------+
type NodeAttrFlags struct {
	OFlag bool `json:"o_flag"`
	TFlag bool `json:"t_flag"`
	EFlag bool `json:"e_flag"`
	BFlag bool `json:"b_flag"`
	RFlag bool `json:"r_flag"`
	VFlag bool `json:"v_flag"`
}

func UnmarshalNodeAttrFlags(b []byte) (*NodeAttrFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal Node Attribute Flags")
	}
	if glog.V(6) {
		glog.Infof("Node Attr Flags Raw: %s", tools.MessageHex(b))
	}
	f := &NodeAttrFlags{}
	f.OFlag = b[0]&0x80 == 0x80
	f.TFlag = b[0]&0x40 == 0x40
	f.EFlag = b[0]&0x20 == 0x20
	f.BFlag = b[0]&0x10 == 0x10
	f.RFlag = b[0]&0x08 == 0x08
	f.VFlag = b[0]&0x04 == 0x04

	return f, nil
}
