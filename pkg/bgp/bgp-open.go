package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// OpenMessage defines BGP Open Message structure
type OpenMessage struct {
	Length             int16
	Type               byte
	Version            byte
	MyAS               uint16
	HoldTime           int16
	BGPID              []byte
	OptParamLen        byte
	OptionalParameters []InformationalTLV
}

// GetCapabilities returns a slice of Capabilities attributes found in Informational TLV slice
func (o *OpenMessage) GetCapabilities() []Capability {
	cap := make([]Capability, 0)
	for _, t := range o.OptionalParameters {
		if t.Type != 2 {
			continue
		}
		c, err := UnmarshalBGPInformationalTLVCapability(t.Value)
		if err != nil {
			continue
		}
		cap = append(cap, c...)
	}

	return cap
}

// Is4BytesASCapable returns true or false if Open message originated by 4 bytes AS capable speaker
// in case of true, it also returns 4 bytes Autonomous System Number.
func (o *OpenMessage) Is4BytesASCapable() (int32, bool) {
	for _, t := range o.OptionalParameters {
		if t.Type != 2 {
			continue
		}
		caps, err := UnmarshalBGPInformationalTLVCapability(t.Value)
		if err != nil {
			continue
		}
		for _, cap := range caps {
			// 65 is 4 Bytes AS Capability code
			if cap.Code != 65 {
				continue
			}
			return int32(binary.BigEndian.Uint32(cap.Value)), true
		}
	}

	return 0, false
}

// IsMultiLabelCapable returns true or false if Open message originated by a bgp speaker
// supporting Multiple Label Capability
func (o *OpenMessage) IsMultiLabelCapable() bool {
	for _, t := range o.OptionalParameters {
		if t.Type == 8 {
			return true
		}
	}

	return false
}

// UnmarshalBGPOpenMessage validate information passed in byte slice and returns BGPOpenMessage object
func UnmarshalBGPOpenMessage(b []byte) (*OpenMessage, error) {
	glog.V(6).Infof("BGPOpenMessage Raw: %s", tools.MessageHex(b))
	var err error
	p := 0
	m := OpenMessage{
		BGPID: make([]byte, 4),
	}
	m.Length = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if b[p] != 1 {
		return nil, fmt.Errorf("invalid message type %d for BGP Open Message", b[p])
	}
	m.Type = b[p]
	p++
	if b[p] != 4 {
		return nil, fmt.Errorf("invalid message version %d for BGP Open Message", b[p])
	}
	m.Version = b[p]
	p++
	m.MyAS = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	m.HoldTime = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	copy(m.BGPID, b[p:p+4])
	p += 4
	m.OptParamLen = b[p]
	p++
	if m.OptParamLen != 0 {
		m.OptionalParameters, err = UnmarshalBGPTLV(b[p : p+int(m.OptParamLen)])
		if err != nil {
			return nil, err
		}
	}

	return &m, nil
}
