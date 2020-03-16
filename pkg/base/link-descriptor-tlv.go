package base

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// LinkDescriptorTLV defines Link Descriptor TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.2
type LinkDescriptorTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (ltlv *LinkDescriptorTLV) String() string {
	var s string
	switch ltlv.Type {
	case 258:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (Link Local/Remote Identifiers)\n", ltlv.Type)
		s += fmt.Sprintf("      Link Local Identifier: %d\n", binary.BigEndian.Uint16(ltlv.Value[:4]))
		s += fmt.Sprintf("      Link Remote Identifier: %d\n", binary.BigEndian.Uint16(ltlv.Value[4:]))
	case 259:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv4 interface address)\n", ltlv.Type)
		s += fmt.Sprintf("      IPv4 interface address: %s\n", net.IP(ltlv.Value).To4().String())
	case 260:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv4 neighbor address)\n", ltlv.Type)
		s += fmt.Sprintf("      IPv4 neighbor address: %s\n", net.IP(ltlv.Value).To4().String())
	case 261:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv6 interface address)\n", ltlv.Type)
		s += fmt.Sprintf("      IPv6 interface address: %s\n", net.IP(ltlv.Value).To16().String())
	case 262:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv6 neighbor address)\n", ltlv.Type)
		s += fmt.Sprintf("      IPv6 neighbor address: %s\n", net.IP(ltlv.Value).To16().String())
	case 263:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (Multi-Topology Identifier)\n", ltlv.Type)
		mit, err := UnmarshalMultiTopologyIdentifierTLV(ltlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += mit.String()
	default:
		s += fmt.Sprintf("   Link Descriptor TLV Type: %d\n", ltlv.Type)
		s += fmt.Sprintf("   Link Descriptor TLV Length: %d\n", ltlv.Length)
		s += "      Value: "
		s += internal.MessageHex(ltlv.Value)
		s += "\n"
	}

	return s
}

// UnmarshalLinkDescriptorTLV builds Link Descriptor TLVs object
func UnmarshalLinkDescriptorTLV(b []byte) ([]LinkDescriptorTLV, error) {
	glog.V(6).Infof("LinkDescriptorTLV Raw: %s", internal.MessageHex(b))
	ltlvs := make([]LinkDescriptorTLV, 0)
	for p := 0; p < len(b); {
		ltlv := LinkDescriptorTLV{}
		ltlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ltlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		ltlv.Value = make([]byte, ltlv.Length)
		copy(ltlv.Value, b[p:p+int(ltlv.Length)])
		ltlvs = append(ltlvs, ltlv)
		p += int(ltlv.Length)
	}

	return ltlvs, nil
}
