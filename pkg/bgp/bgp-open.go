package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

const (
	// BGPMinOpenMessageLength defines a minimum length of BGP Open Message
	BGPMinOpenMessageLength = 29
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
	Capabilities       Capability
}

// GetCapabilities returns a slice of Capabilities attributes found in Informational TLV slice
func (o *OpenMessage) GetCapabilities() Capability {
	return o.Capabilities
}

// Is4BytesASCapable returns true or false if Open message originated by 4 bytes AS capable speaker
// in case of true, it also returns 4 bytes Autonomous System Number.
func (o *OpenMessage) Is4BytesASCapable() (uint32, bool) {
	v, ok := o.Capabilities[65]
	if !ok {
		return 0, false
	}

	return binary.BigEndian.Uint32(v[0].Value), true
}

// IsMultiLabelCapable returns true or false if Open message originated by a bgp speaker
// supporting Multiple Label Capability
func (o *OpenMessage) IsMultiLabelCapable() bool {
	if _, ok := o.Capabilities[8]; ok {
		return true
	}

	return false
}

// UnmarshalBGPOpenMessage validate information passed in byte slice and returns BGPOpenMessage object
func UnmarshalBGPOpenMessage(b []byte) (*OpenMessage, error) {
	if glog.V(6) {
		glog.Infof("BGPOpenMessage Raw: %s", tools.MessageHex(b))
	}
	if len(b) < BGPMinOpenMessageLength-16 {
		return nil, fmt.Errorf("BGP Open Message length %d is invalid", len(b))
	}
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
		if m.OptionalParameters, m.Capabilities, err = UnmarshalBGPTLV(b[p : p+int(m.OptParamLen)]); err != nil {
			return nil, err
		}
	}

	return &m, nil
}
