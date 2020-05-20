package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// SIDStructureSubSubTLV defines a structure of SID's Structure Sub Sub TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SIDStructureSubSubTLV struct {
	LocalBlockLength    uint8 `json:"local_block_length,omitempty"`
	LocalNodeLength     uint8 `json:"local_node_length,omitempty"`
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
	tlv.LocalNodeLength = b[p]
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
	SID              string                `json:"sid,omitempty"`
	Flags            uint8                 `json:"flags,omitempty"`
	EndpointBehavior uint16                `json:"endpoint_behavior,omitempty"`
	SubSubTLVs       map[uint8][]SubSubTLV `json:"sub_sub_tlvs,omitempty"`
}

// UnmarshalJSON unmarshals a slice of byte into SRv6 InformationSubTLV object
func (istlv *InformationSubTLV) UnmarshalJSON(b []byte) error {
	type informationSubTLV InformationSubTLV
	if err := json.Unmarshal(b, (*informationSubTLV)(istlv)); err != nil {
		return err
	}
	istlv.SubSubTLVs = make(map[uint8][]SubSubTLV)
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	var subsubtlvs map[string]json.RawMessage
	if err := json.Unmarshal(objmap["sub_sub_tlvs"], &subsubtlvs); err != nil {
		return nil
	}
	for subsubtlvType, subsubtlvValue := range subsubtlvs {
		t, err := strconv.Atoi(subsubtlvType)
		if err != nil {
			return err
		}
		sstlvs, ok := istlv.SubSubTLVs[uint8(t)]
		if !ok {
			istlv.SubSubTLVs[uint8(t)] = make([]SubSubTLV, 0)
		}
		switch t {
		case 1:
			istlvs := make([]*SIDStructureSubSubTLV, 0)
			if err := json.Unmarshal(subsubtlvValue, &istlvs); err != nil {
				return err
			}
			for _, e := range istlvs {
				var s SubTLV
				s = e
				sstlvs = append(sstlvs, s)
			}
		default:
			return fmt.Errorf("unknown SRv6 L3 Service Sub Sub TLV type %d", t)
		}
		istlv.SubSubTLVs[uint8(t)] = sstlvs
	}

	return nil
}

// UnmarshalInformationSubTLV instantiates Information SubT LV
func UnmarshalInformationSubTLV(b []byte) (*InformationSubTLV, error) {
	// Skip Resrved byte
	p := 1
	tlv := &InformationSubTLV{}
	tlv.SID = net.IP(b[p : p+16]).To16().String()
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
		tlv.SubSubTLVs = stlv
	}
	return tlv, nil
}

// SubTLV defines SRv6 Service's Sub TLV object
type SubTLV interface{}

// SubSubTLV defines SRv6 Service's Sub Sub TLV object
type SubSubTLV interface{}

// L3Service defines SRv6 L3 Service message structure
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2
type L3Service struct {
	SubTLVs map[uint8][]SubTLV `json:"sub_tlvs,omitempty"`
}

// UnmarshalJSON unmarshals a slice of byte into L3Service object
func (l3s *L3Service) UnmarshalJSON(b []byte) error {
	l3s.SubTLVs = make(map[uint8][]SubTLV)
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	var subtlvs map[string]json.RawMessage
	if err := json.Unmarshal(objmap["sub_tlvs"], &subtlvs); err != nil {
		return err
	}
	for subtlvType, subtlvValue := range subtlvs {
		t, err := strconv.Atoi(subtlvType)
		if err != nil {
			return err
		}
		stlvs, ok := l3s.SubTLVs[uint8(t)]
		if !ok {
			l3s.SubTLVs[uint8(t)] = make([]SubTLV, 0)
		}
		switch t {
		case 1:
			istlvs := make([]*InformationSubTLV, 0)
			if err := json.Unmarshal(subtlvValue, &istlvs); err != nil {
				return err
			}
			for _, e := range istlvs {
				var s SubTLV
				s = e
				stlvs = append(stlvs, s)
			}
		default:
			return fmt.Errorf("unknown SRv6 L3 Service Sub TLV type %d", t)
		}
		l3s.SubTLVs[uint8(t)] = stlvs
	}

	return nil
}

// UnmarshalSRv6L3Service instantiate from the slice of byte SRv6 L3 Service Object
func UnmarshalSRv6L3Service(b []byte) (*L3Service, error) {
	glog.V(6).Infof("SRv6 L3 Service Raw: %s", tools.MessageHex(b))
	l3 := L3Service{
		SubTLVs: make(map[uint8][]SubTLV),
	}
	// Skipping reserved byte
	stlv, err := UnmarshalSRv6L3ServiceSubTLV(b[1:])
	if err != nil {
		return nil, err
	}
	l3.SubTLVs = stlv

	return &l3, nil
}

// UnmarshalSRv6L3ServiceSubTLV instantiates L3 Service Sub TLV
func UnmarshalSRv6L3ServiceSubTLV(b []byte) (map[uint8][]SubTLV, error) {
	m := make(map[uint8][]SubTLV)
	var err error
	for p := 0; p < len(b); {
		t := b[p]
		p++
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		var s SubTLV
		switch t {
		case 1:
			if s, err = UnmarshalInformationSubTLV(b[p : p+int(l)]); err != nil {
				return nil, err
			}
		default:
			s = make([]byte, l)
			copy(s.([]byte), b[p:p+int(l)])
		}
		stlv, ok := m[t]
		if !ok {
			stlv = make([]SubTLV, 0)
			m[t] = stlv
		}
		stlv = append(stlv, s)
		m[t] = stlv
		p += int(l)
	}
	return m, nil
}

// UnmarshalSRv6L3ServiceSubSubTLV instantiates L3 Service Sub TLV
func UnmarshalSRv6L3ServiceSubSubTLV(b []byte) (map[uint8][]SubSubTLV, error) {
	var err error
	m := make(map[uint8][]SubSubTLV)
	for p := 1; p < len(b); {
		t := b[p]
		p++
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		var s SubSubTLV
		switch t {
		case 1:
			if s, err = UnmarshalSIDStructureSubSubTLV(b[p : p+int(l)]); err != nil {
			}
		default:
			s = make([]byte, l)
			copy(s.([]byte), b[p:p+int(l)])
		}
		stlv, ok := m[t]
		if !ok {
			stlv = make([]SubSubTLV, 0)
			m[t] = stlv
		}
		stlv = append(stlv, s)
		m[t] = stlv
		p += int(l)
	}
	return m, nil
}
