package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/sbezverk/gobmp/pkg/base"
)

// SIDDescriptor defines SRv6 SID Descriptor Object
type SIDDescriptor struct {
	InformationTLV          *SIDInformationTLV
	MultiTopologyIdentifier *base.MultiTopologyIdentifierTLV
}

func (srd *SIDDescriptor) String() string {
	var s string
	s += "SRv6 SID Descriptor Object:" + "\n"
	if srd.InformationTLV != nil {
		s += srd.InformationTLV.String()
	}
	if srd.MultiTopologyIdentifier != nil {
		s += srd.MultiTopologyIdentifier.String()
	}

	return s
}

// UnmarshalSRv6SIDDescriptor build SRv6 Descriptor Object
func UnmarshalSRv6SIDDescriptor(b []byte) (*SIDDescriptor, error) {
	srd := SIDDescriptor{}
	for p := 0; p < len(b); {
		t := binary.BigEndian.Uint16(b[p : p+2])
		switch t {
		case 518:
			l := binary.BigEndian.Uint16(b[p+2 : p+4])
			inf, err := UnmarshalSRv6SIDInformationTLV(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			srd.InformationTLV = inf
			p += 2      // Type
			p += 2      // Length
			p += int(l) // Actual TLV length
		case 263:
			l := binary.BigEndian.Uint16(b[p+2 : p+4])
			mti, err := base.UnmarshalMultiTopologyIdentifierTLV(b[p : p+int(l)])
			if err != nil {
				return nil, err
			}
			srd.MultiTopologyIdentifier = mti
			p += 2      // Type
			p += 2      // Length
			p += int(l) // Actual TLV length
		default:
			return nil, fmt.Errorf("invalid SRv6 SID Descriptor Type: %d", t)
		}
	}

	return &srd, nil
}
