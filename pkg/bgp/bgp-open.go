package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// BGPMinOpenMessageLength defines a minimum length of BGP Open Message
	BGPMinOpenMessageLength = 29
	BGPMessageMarkerLength  = 16
)

// OpenMessage defines BGP Open Message structure
type OpenMessage struct {
	Length             uint16
	Type               byte
	Version            byte
	MyAS               uint16
	HoldTime           uint16
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

// AddPathCapability returns a map of NLRI types and bool indicating if a particular NLRI type
// supports Add Path capability
func (o *OpenMessage) AddPathCapability() map[int]bool {
	m := make(map[int]bool)
	v, ok := o.Capabilities[69]
	if !ok {
		return m
	}
	if len(v) == 0 || len(v) > 1 {
		glog.Errorf("invalid length %d of AddPath capability", len(v))
		return m
	}
	if glog.V(6) {
		glog.Infof("AddPath Capability Raw: %s", tools.MessageHex(v[0].Value))
	}
	// Check for Capability data consistency
	if len(v[0].Value)%4 != 0 {
		glog.Errorf("invalid length of AddPath capability %d", len(v[0].Value))
		return m
	}
	for p := 0; p < len(v[0].Value); p += 4 {
		afi := binary.BigEndian.Uint16(v[0].Value[p : p+2])
		safi := v[0].Value[p+2]
		// Check if last byte == 3 (Send/Receive) AddPath, if not, ignoring entry
		flag := false
		if v[0].Value[p+3] == 3 {
			flag = true
		}
		m[NLRIMessageType(afi, safi)] = flag
		if glog.V(6) {
			glog.Infof("AddPath Capability for AFI/SAFI: %d/%d is %t", afi, safi, flag)
		}
	}

	return m
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
	if len(b) < BGPMinOpenMessageLength-BGPMessageMarkerLength {
		return nil, fmt.Errorf("BGP Open Message length %d is invalid", len(b))
	}
	var err error
	p := 0
	m := OpenMessage{
		BGPID: make([]byte, 4),
	}
	m.Length = binary.BigEndian.Uint16(b[p : p+2])
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
	m.HoldTime = binary.BigEndian.Uint16(b[p : p+2])
	switch {
	case m.HoldTime == 0:
		fallthrough
	case m.HoldTime >= 3:
	default:
		return nil, fmt.Errorf("invalid Hold Time %d for BGP Open Message", m.HoldTime)
	}

	p += 2
	copy(m.BGPID, b[p:p+4])
	// According to RFC 6286 BGP ID of 0.0.0.0 is invalid for BGP Open Message
	if bytes.Equal(m.BGPID, []byte{0, 0, 0, 0}) {
		return nil, fmt.Errorf("invalid BGP ID %v for BGP Open Message", m.BGPID)
	}
	p += 4
	m.OptParamLen = b[p]
	p++
	if m.OptParamLen != 0 {
		optStart := p
		optEnd := p + int(m.OptParamLen)
		extendedParamLen := false
		// RFC 9072: if OptParamLen == 255 and the next byte is also 255 (Non-Ext OP Type),
		// the Optional Parameters use the extended encoding with a 2-byte total length field
		// and 2-byte individual parameter length fields.
		if m.OptParamLen == 255 && p < len(b) && b[p] == 255 {
			if p+3 > len(b) {
				return nil, fmt.Errorf("BGP Open Message too short for RFC 9072 extended Optional Parameters header")
			}
			extLen := int(binary.BigEndian.Uint16(b[p+1 : p+3]))
			optStart = p + 3 // skip Non-Ext OP Type (1 byte) + Extended Opt. Parm. Length (2 bytes)
			optEnd = optStart + extLen
			extendedParamLen = true
			if optEnd > len(b) {
				return nil, fmt.Errorf("RFC 9072 extended Optional Parameters length %d exceeds buffer of %d bytes", extLen, len(b)-optStart)
			}
		}
		if !extendedParamLen && optEnd > len(b) {
			return nil, fmt.Errorf("Optional Parameters length %d exceeds buffer of %d bytes", m.OptParamLen, len(b)-optStart)
		}
		if m.OptionalParameters, m.Capabilities, err = unmarshalTLVs(b[optStart:optEnd], extendedParamLen); err != nil {
			return nil, err
		}
	}

	return &m, nil
}
