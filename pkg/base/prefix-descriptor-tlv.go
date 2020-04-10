package base

import (
	"encoding/binary"
	"encoding/json"
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

// MarshalJSON defines a method to Marshal Prefix Descriptor TLV object into JSON format
func (tlv *PrefixDescriptorTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	var b []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", tlv.Type))...)
	jsonData = append(jsonData, []byte("\"Description\":")...)
	switch tlv.Type {
	case 263:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Multi-Topology Identifier\","))...)
		jsonData = append(jsonData, []byte("\"multiTopologyIdentifier\":")...)
		mit, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(mit)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 264:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"OSPF Route Type\","))...)
		jsonData = append(jsonData, []byte("\"ospfRouteType\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", tlv.Value))...)
	case 265:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IP Reachability Information\","))...)
		jsonData = append(jsonData, []byte("\"ipReachabilityInformation\":")...)
		ipr, err := UnmarshalIPReachabilityInformation(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(ipr)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	default:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Unknown Prefix TLV\","))...)
		jsonData = append(jsonData, []byte("\"Value\":")...)
		jsonData = append(jsonData, tools.RawBytesToJSON(tlv.Value)...)
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalPrefixDescriptorTLV builds Prefix Descriptor Sub TLVs object
func UnmarshalPrefixDescriptorTLV(b []byte) ([]PrefixDescriptorTLV, error) {
	glog.V(5).Infof("PrefixDescriptorTLV Raw: %s", tools.MessageHex(b))
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
