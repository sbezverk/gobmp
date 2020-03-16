package bgpls

// NLRI defines BGP-LS NLRI object as collection of BGP-LS TLVs
// https://tools.ietf.org/html/rfc7752#section-3.3
type NLRI struct {
	LSTLV []TLV
}

func (ls *NLRI) String() string {
	var s string

	s += "BGP-LS TLVs:" + "\n"
	for _, tlv := range ls.LSTLV {
		s += tlv.String()
	}

	return s
}

// UnmarshalBGPLSNLRI builds Prefix NLRI object
func UnmarshalBGPLSNLRI(b []byte) (*NLRI, error) {
	bgpls := NLRI{}
	ls, err := UnmarshalBGPLSTLV(b)
	if err != nil {
		return nil, err
	}
	bgpls.LSTLV = ls

	return &bgpls, nil
}
