package sr

// SIDTLV defines SID Sub tlv object
type SIDTLV struct {
	Type   uint16 `json:"-"`
	Length uint16 `json:"-"`
	Value  []byte `json:"sid,omitempty"`
}
