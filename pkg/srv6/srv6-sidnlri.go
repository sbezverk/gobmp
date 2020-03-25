package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SIDNLRI defines SRv6 SID NLRI onject
// Mp RFC yet
type SIDNLRI struct {
	ProtocolID uint8
	Identifier uint64
	LocalNode  *base.NodeDescriptor
	SRv6SID    *SIDDescriptor
}

func (sr *SIDNLRI) String() string {
	var s string
	s += fmt.Sprintf("Protocol ID: %s\n", internal.ProtocolIDString(sr.ProtocolID))
	s += fmt.Sprintf("Identifier: %d\n", sr.Identifier)
	s += sr.LocalNode.String()
	s += sr.SRv6SID.String()

	return s
}

// MarshalJSON defines a method to Marshal SRv6 SID NLRI object into JSON format
func (sr *SIDNLRI) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"protocolID\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", sr.ProtocolID))...)
	jsonData = append(jsonData, []byte("\"identifier\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", sr.Identifier))...)
	jsonData = append(jsonData, []byte("\"localNode\":")...)
	if sr.LocalNode != nil {
		b, err := json.Marshal(sr.LocalNode)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		jsonData = append(jsonData, ',')
	} else {
		jsonData = append(jsonData, "{},"...)
	}
	jsonData = append(jsonData, []byte("\"SRv6SID\":")...)
	if sr.SRv6SID != nil {
		b, err := json.Marshal(sr.SRv6SID)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	} else {
		jsonData = append(jsonData, "{}"...)
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRv6SIDNLRI builds SRv6SIDNLRI NLRI object
func UnmarshalSRv6SIDNLRI(b []byte) (*SIDNLRI, error) {
	glog.V(6).Infof("SRv6 SID NLRI Raw: %s", internal.MessageHex(b))
	sr := SIDNLRI{
		SRv6SID: &SIDDescriptor{},
	}
	p := 0
	sr.ProtocolID = b[p]
	p++
	// Skip reserved bytes
	//	p += 3
	sr.Identifier = binary.BigEndian.Uint64(b[p : p+8])
	p += 8
	// Get Node Descriptor's length, skip Node Descriptor Type
	l := binary.BigEndian.Uint16(b[p+2 : p+4])
	ln, err := base.UnmarshalNodeDescriptor(b[p : p+int(l)])
	if err != nil {
		return nil, err
	}
	sr.LocalNode = ln
	// Skip Node Descriptor Type and Length 4 bytes
	p += 4
	p += int(l)
	srd, err := UnmarshalSRv6SIDDescriptor(b[p:len(b)])
	if err != nil {
		return nil, err
	}
	sr.SRv6SID = srd

	return &sr, nil
}
