package srv6

import "github.com/sbezverk/gobmp/pkg/base"

// SIDStructureSubSubTLV defines a structure of SID's Structure Sub Sub TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SIDStructureSubSubTLV struct {
	Type                uint8  `json:"-"`
	Length              uint16 `json:"-"`
	LocalBlockLength    uint8  `json:"local_block_length,omitempty"`
	LocatorNodeLength   uint8  `json:"locator_node_length,omitempty"`
	FunctionLength      uint8  `json:"function_length,omitempty"`
	ArgumentLength      uint8  `json:"argument_length,omitempty"`
	TranspositionLength uint8  `json:"transposition_length,omitempty"`
	TranspositionOffset uint8  `json:"transposition_offset,omitempty"`
}

// ServiceSubSubTLV defines the structure of Service's Sib Sub Service TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2
type ServiceSubSubTLV struct {
	SIDStructure *SIDStructureSubSubTLV
	Unclassified map[uint16]base.TLV
}

// InformationSubTLV defines a structure of SRv6 Information Sub TLV (type 1)
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.1
type InformationSubTLV struct {
	Type             uint8
	Length           uint16
	SID              []byte
	Flags            uint8
	EndpointBehavior uint16
	SubSubTLV        *ServiceSubSubTLV
	Unclassified     map[uint16]base.TLV
}

// L3Service defines SRv6 L3 Service message structure
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2
type L3Service struct {
	Type              uint8
	Length            uint16
	InformationSubTLV *InformationSubTLV
	Unclassified      map[uint16]base.TLV
}

// UnmarshalSRv6L3Service instantiate from the slice of byte SRv6 L3 Service Object
func UnmarshalSRv6L3Service(b []byte) (*L3Service, error) {
	l3 := L3Service{}
	return &l3, nil
}
