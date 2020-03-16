package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// PrefixDescriptorTLV defines Prefix Descriptor Sub TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type PrefixDescriptorTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (stlv *PrefixDescriptorTLV) String() string {
	var s string
	switch stlv.Type {
	case 263:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (Multi-Topology Identifier)\n", stlv.Type)
		mit, err := UnmarshalMultiTopologyIdentifierTLV(stlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += mit.String()
	case 264:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (OSPF Route Type)\n", stlv.Type)
		s += fmt.Sprintf("      OSPF Route Type: %d\n", stlv.Value)
	case 265:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d (IP Reachability Information)\n", stlv.Type)
		s += fmt.Sprintf("      IP Reachability Information:\n")
		s += fmt.Sprintf("         Prefix length: %d bytes\n", stlv.Value[0]/8)
		s += fmt.Sprintf("         IP Prefix: %s\n", internal.MessageHex(stlv.Value[1:]))
	default:
		s += fmt.Sprintf("   Prefix Descriptor TLV Type: %d\n", stlv.Type)
		s += fmt.Sprintf("   Prefix Descriptor TLV Length: %d\n", stlv.Length)
		s += "      Value: "
		s += internal.MessageHex(stlv.Value)
		s += "\n"
	}

	return s
}

// UnmarshalPrefixDescriptorTLV builds Prefix Descriptor Sub TLVs object
func UnmarshalPrefixDescriptorTLV(b []byte) ([]PrefixDescriptorTLV, error) {
	glog.V(6).Infof("PrefixDescriptorTLV Raw: %s", internal.MessageHex(b))
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
