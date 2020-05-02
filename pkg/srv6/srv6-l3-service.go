package srv6

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SIDStructureSubSubTLV defines a structure of SID's Structure Sub Sub TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SIDStructureSubSubTLV struct {
	LocalBlockLength    uint8 `json:"local_block_length,omitempty"`
	LocatorNodeLength   uint8 `json:"locator_node_length,omitempty"`
	FunctionLength      uint8 `json:"function_length,omitempty"`
	ArgumentLength      uint8 `json:"argument_length,omitempty"`
	TranspositionLength uint8 `json:"transposition_length,omitempty"`
	TranspositionOffset uint8 `json:"transposition_offset,omitempty"`
}

// UnmarshalSIDStructureSubSubTLV instantiates SID Structure Sub Sub TLV
func UnmarshalSIDStructureSubSubTLV(b []byte) (*SIDStructureSubSubTLV, error) {
	// Skip Resrved byte
	p := 0
	tlv := &SIDStructureSubSubTLV{}
	tlv.LocalBlockLength = b[p]
	p++
	tlv.LocatorNodeLength = b[p]
	p++
	tlv.FunctionLength = b[p]
	p++
	tlv.ArgumentLength = b[p]
	p++
	tlv.TranspositionLength = b[p]
	p++
	tlv.TranspositionOffset = b[p]

	return tlv, nil
}

// InformationSubTLV defines a structure of SRv6 Information Sub TLV (type 1)
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.1
type InformationSubTLV struct {
	SID              []byte                   `json:"information_sub_tlv_sid,omitempty"`
	Flags            uint8                    `json:"information_sub_tlv_flags,omitempty"`
	EndpointBehavior uint16                   `json:"information_sub_tlv_endpoint_behavior,omitempty"`
	SubSubTLV        map[uint8]*ServiceSubTLV `json:"sub_sub_tlv,omitempty"`
}

// UnmarshalInformationSubTLV instantiates Information SubT LV
func UnmarshalInformationSubTLV(b []byte) (*InformationSubTLV, error) {
	// Skip Resrved byte
	p := 1
	tlv := &InformationSubTLV{}
	tlv.SID = make([]byte, 16)
	copy(tlv.SID, b[p:p+16])
	p += 16
	tlv.Flags = b[p]
	p++
	tlv.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p < len(b) {
		stlv, err := UnmarshalSRv6L3ServiceSubSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		tlv.SubSubTLV = stlv
	}
	return tlv, nil
}

// ServiceSubTLV defines SRv6 Service's TLV object, it is used as Service Sub TLV and Sub Sub TLV
type ServiceSubTLV struct {
	Type   uint8       `json:"-"`
	Length uint16      `json:"-"`
	Value  interface{} `json:"key_value,omitempty"`
}

// L3Service defines SRv6 L3 Service message structure
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2
type L3Service struct {
	ServiceSubTLV map[uint8]*ServiceSubTLV `json:"service_sub_tlv,omitempty"`
}

// UnmarshalSRv6L3Service instantiate from the slice of byte SRv6 L3 Service Object
func UnmarshalSRv6L3Service(b []byte) (*L3Service, error) {
	glog.V(6).Infof("SRv6 L3 Service Raw: %s", tools.MessageHex(b))
	l3 := L3Service{
		ServiceSubTLV: make(map[uint8]*ServiceSubTLV),
	}
	// Skipping reserved byte
	stlv, err := UnmarshalSRv6L3ServiceSubTLV(b[1:])
	if err != nil {
		return nil, err
	}
	l3.ServiceSubTLV = stlv

	return &l3, nil
}

// UnmarshalSRv6L3ServiceSubTLV instantiates L3 Service Sub TLV
func UnmarshalSRv6L3ServiceSubTLV(b []byte) (map[uint8]*ServiceSubTLV, error) {
	m := make(map[uint8]*ServiceSubTLV)
	for p := 0; p < len(b); {
		t := b[p]
		p++
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		s := ServiceSubTLV{
			Type:   t,
			Length: l,
		}
		switch t {
		case 1:
			if stlv, err := UnmarshalInformationSubTLV(b[p : p+int(l)]); err == nil {
				s.Value = stlv
			}
		default:
			s.Value = make([]byte, l)
			copy(s.Value.([]byte), b[p:p+int(l)])
		}
		m[t] = &s
		p += int(l)
	}
	return m, nil
}

// UnmarshalSRv6L3ServiceSubSubTLV instantiates L3 Service Sub TLV
func UnmarshalSRv6L3ServiceSubSubTLV(b []byte) (map[uint8]*ServiceSubTLV, error) {
	m := make(map[uint8]*ServiceSubTLV)
	for p := 1; p < len(b); {
		t := b[p]
		p++
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		s := ServiceSubTLV{
			Type:   t,
			Length: l,
		}
		switch t {
		case 1:
			if stlv, err := UnmarshalSIDStructureSubSubTLV(b[p : p+int(l)]); err == nil {
				s.Value = stlv
			}
		default:
			s.Value = make([]byte, l)
			copy(s.Value.([]byte), b[p:p+int(l)])
		}
		m[t] = &s
		p += int(l)
	}
	return m, nil
}
