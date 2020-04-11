package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixDescriptorTLV defines Prefix Descriptor Sub TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type PrefixDescriptorTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (tlv *PrefixDescriptorTLV) String() string {
	var s string
	switch tlv.Type {
	case 263:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (Multi-Topology Identifier)\n", tlv.Type)
		mit, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += mit.String()
	case 264:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (OSPF Route Type)\n", tlv.Type)
		s += fmt.Sprintf("      OSPF Route Type: %d\n", tlv.Value)
	case 265:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (IP Reachability Information)\n", tlv.Type)
		ipr, err := UnmarshalIPReachabilityInformation(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += ipr.String()
	default:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d\n", tlv.Type)
		s += fmt.Sprintf("   Prefix Descriptor TLV Length: %d\n", tlv.Length)
		s += "      Value: "
		s += tools.MessageHex(tlv.Value)
		s += "\n"
	}

	return s
}

// UnmarshalPrefixDescriptorTLV builds Prefix Descriptor Sub TLVs object
func UnmarshalPrefixDescriptorTLV(b []byte) ([]PrefixDescriptorTLV, error) {
	glog.V(6).Infof("PrefixDescriptorTLV Raw: %s", tools.MessageHex(b))
	ptlvs := make([]PrefixDescriptorTLV, 0)
	for p := 0; p < len(b); {
		ptlv := PrefixDescriptorTLV{}
		ptlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ptlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ptlv.Value = make([]byte, ptlv.Length)
		copy(ptlv.Value, b[p:p+int(ptlv.Length)])
		p += int(ptlv.Length)
		ptlvs = append(ptlvs, ptlv)
	}

	return ptlvs, nil
}
