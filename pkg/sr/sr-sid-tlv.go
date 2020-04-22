package sr

// SIDTLV defines SID Sub tlv object
type SIDTLV struct {
	Type   uint16
	Length uint16
	Value  []byte `json:"sid,omitempty"`
}
