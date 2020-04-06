package l3vpn

// Label defines a structure of a single label
type Label struct {
	Value uint32
	Exp   uint8 // 3 bits
	BoS   bool  // 1 bit
	TTL   uint8 // 8 bits
}

func NewLabel(b []byte) Label {
	return Label{}
}

// RD defines a structure of VPN prefixe's Route Distinguisher
type RD struct {
	Type  uint16
	Value []byte
}

// GetRD returns a string representation of RD (one of three types)
func (rd *RD) GetRD() string {
	var s string

	return s
}

// NLRI defines L3 VPN NLRI object
type NLRI struct {
	Length uint8
	Labels []Label
	RD     RD
	Prefix []byte
}

// UnmarshalL3VPNNLRI instantiates a L3 VPN NLRI object
func UnmarshalL3VPNNLRI(b []byte) (*NLRI, error) {
	n := NLRI{}
	p := 0
	// Getting length of NLRI in bytes
	n.Length = uint8(b[p] / 8)
	p++
	n.Labels = make([]Label, 0)
	// subtract 12 for the length as label stack follows by RD 8 bytes and prefix 4 bytes
	for p < len(b)-12 {
		l := NewLabel(b[p : p+3])
		n.Labels = append(n.Labels, l)
		p += 3
	}

	return nil, nil
}
