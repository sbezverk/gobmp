package bgp

import (
	"encoding/binary"
	"fmt"
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

// UnmarshalBGPOpenMessage validate information passed in byte slice and returns BGPOpenMessage object
func UnmarshalBGPOpenMessage(b []byte) (*OpenMessage, error) {
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
