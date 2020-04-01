package sr

type SIDTLV struct {
	Type   uint16
	Length uint16
	SID    []byte
}
