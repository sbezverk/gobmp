package srv6

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// SIDDescriptor defines SRv6 SID Descriptor Object
type SIDDescriptor struct {
	SID             []byte `json:"srv6_sid,omitempty"`
	MultiTopologyID []*base.MultiTopologyIdentifier
}

// GetMTID returns a slice of MTI found in Multi Topology Identifier object
func (sd *SIDDescriptor) GetMTID() []*base.MultiTopologyIdentifier {
	return sd.MultiTopologyID
}

// UnmarshalSRv6SIDDescriptor build SRv6 Descriptor Object
func UnmarshalSRv6SIDDescriptor(b []byte) (*SIDDescriptor, error) {
	if glog.V(6) {
		glog.Infof("SRv6 SID Descriptor Raw: %s", tools.MessageHex(b))
	}
	srd := SIDDescriptor{}
	for p := 0; p < len(b); {
		t := binary.BigEndian.Uint16(b[p : p+2])
		var l uint16
		switch t {
		case 518:
			l = binary.BigEndian.Uint16(b[p+2 : p+4])
			srd.SID = make([]byte, int(l))
			copy(srd.SID, b[p+4:p+4+int(l)])
		case 263:
			l = binary.BigEndian.Uint16(b[p+2 : p+4])
			mti, err := base.UnmarshalMultiTopologyIdentifierTLV(b[p+4 : p+4+int(l)])
			if err != nil {
				return nil, err
			}
			srd.MultiTopologyID = mti
		default:
			return nil, fmt.Errorf("invalid SRv6 SID Descriptor Type: %d", t)
		}
		p += 2      // Type
		p += 2      // Length
		p += int(l) // Actual TLV length
	}

	return &srd, nil
}
