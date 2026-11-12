package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// InitiationMessage defines BMP Initiation Message per rfc7854
type InitiationMessage struct {
	TLV []InformationalTLV
}

// UnmarshalInitiationMessage processes Initiation Message and returns BMPInitiationMessage object
func UnmarshalInitiationMessage(b []byte) (*InitiationMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Initiation Message Raw: %s", tools.MessageHex(b))
	}
	im := &InitiationMessage{
		TLV: make([]InformationalTLV, 0),
	}
	if len(b) == 0 {
		// rfc7854 Section 4.3 requires sysDescr and sysName, but an empty Initiation is accepted and decodes to no TLVs
		return im, nil
	}
	for i := 0; i < len(b); {
		if i+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode Initiation message TLV type, need 2 bytes, have %d", len(b)-i)
		}
		// Extracting TLV type 2 bytes
		t := binary.BigEndian.Uint16(b[i : i+2])
		// Extracting TLV length 2 bytes
		if i+4 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode Initiation message TLV length, need 2 bytes, have %d", len(b)-(i+2))
		}
		l := binary.BigEndian.Uint16(b[i+2 : i+4])
		if int(l) > len(b)-(i+4) {
			return nil, fmt.Errorf("not enough bytes to decode Initiation message TLV value, need %d bytes, have %d", l, len(b)-(i+4))
		}
		v := b[i+4 : i+4+int(l)]
		im.TLV = append(im.TLV, InformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return im, nil
}

// Information TLV types carried by the Initiation message, rfc7854 Section 4.4.
const (
	initiationSysDescr = 1
	initiationSysName  = 2
)

// SysDescr returns the first sysDescr string TLV, or "" when there is none.
func (m *InitiationMessage) SysDescr() string {
	return m.firstString(initiationSysDescr)
}

// SysName returns the first sysName string TLV, or "" when there is none.
func (m *InitiationMessage) SysName() string {
	return m.firstString(initiationSysName)
}

func (m *InitiationMessage) firstString(infoType uint16) string {
	for _, t := range m.TLV {
		if t.InformationType == infoType {
			return string(t.Information)
		}
	}
	return ""
}
