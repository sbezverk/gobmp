package srv6

// SIDStructureSubSubTLV defines a structure of SID's Structure Sub Sub TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2.1
type SIDStructureSubSubTLV struct {
	Type                uint8
	Length              uint16
	LocalBlockLength    uint8
	LocatorNodeLength   uint8
	FunctionLength      uint8
	ArgumentLength      uint8
	TranspositionLength uint8
	TranspositionOffset uint8
}

// ServiceSubSubTLV defines the structure of Service's Sib Sub Service TLV
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2.1.2
type ServiceSubSubTLV struct {
	SIDStructure *SIDStructureSubSubTLV
	Unclassified []SubTLV
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
	Unclassified     []SubTLV
}

// L3Service defines SRv6 L3 Service message structure
// https://tools.ietf.org/html/draft-dawra-bess-srv6-services-02#section-2
type L3Service struct {
	Type              uint8
	Length            uint16
	InformationSubTLV *InformationSubTLV
	Unclassified      []SubTLV
}

// UnmarshalSRv6L3Service instantiate from the slice of byte SRv6 L3 Service Object
func UnmarshalSRv6L3Service(b []byte) (*L3Service, error) {
	l3 := L3Service{}
	return &l3, nil
}
