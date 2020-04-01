package sr

type Capability struct {
	Flags uint8
	TLV   []CapabilityTLV
}
