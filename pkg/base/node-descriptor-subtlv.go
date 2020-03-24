package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// NodeDescriptorSubTLV defines Node Descriptor Sub TLVs object
// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
type NodeDescriptorSubTLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (stlv *NodeDescriptorSubTLV) String() string {
	var s string
	switch stlv.Type {
	case 512:
		s += fmt.Sprintf("      Node Descriptor Sub TLV Type: %d (Autonomous System)\n", stlv.Type)
		s += fmt.Sprintf("         Autonomous System: %d\n", binary.BigEndian.Uint32(stlv.Value))
	case 513:
		s += fmt.Sprintf("      Node Descriptor Sub TLV Type: %d (BGP-LS Identifier)\n", stlv.Type)
		s += fmt.Sprintf("         BGP-LS Identifier: %s\n", internal.MessageHex(stlv.Value))
	case 514:
		s += fmt.Sprintf("      Node Descriptor Sub TLV Type: %d (OSPF Area-ID)\n", stlv.Type)
		s += fmt.Sprintf("         OSPF Area-ID: %s\n", internal.MessageHex(stlv.Value))
	case 515:
		s += fmt.Sprintf("      Node Descriptor Sub TLV Type: %d (IGP Router-ID)\n", stlv.Type)
		s += fmt.Sprintf("         IGP Router-ID: %s\n", internal.MessageHex(stlv.Value))
	default:
		s += fmt.Sprintf("      Node Descriptor Sub TLV Type: %d\n", stlv.Type)
		s += fmt.Sprintf("      Node Descriptor Sub TLV Length: %d\n", stlv.Length)
		s += "         Value: "
		s += internal.MessageHex(stlv.Value)
		s += "\n"
	}

	return s
}

// MarshalJSON defines a method to Marshal Node Descriptor Sub TLV object into JSON format
func (stlv *NodeDescriptorSubTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	var b []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", stlv.Type))...)
	jsonData = append(jsonData, []byte("\"Description\":")...)
	switch stlv.Type {
	case 512:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Autonomous System\","))...)
		b = append(b, []byte(fmt.Sprintf("%d", binary.BigEndian.Uint32(stlv.Value)))...)
	case 513:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"BGP-LS Identifier\","))...)
		b = append(b, internal.RawBytesToJSON(stlv.Value)...)
	case 514:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"OSPF Area-ID\","))...)
		b = append(b, internal.RawBytesToJSON(stlv.Value)...)
	case 515:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IGP Router-ID\","))...)
		b = append(b, internal.RawBytesToJSON(stlv.Value)...)
	default:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Unknown Node\","))...)
		b = append(b, []byte("[]")...)
	}
	jsonData = append(jsonData, []byte("\"Value\":")...)
	jsonData = append(jsonData, b...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalNodeDescriptorSubTLV builds Node Descriptor Sub TLVs object
func UnmarshalNodeDescriptorSubTLV(b []byte) ([]NodeDescriptorSubTLV, error) {
	glog.V(6).Infof("NodeDescriptorSubTLV Raw: %s", internal.MessageHex(b))
	stlvs := make([]NodeDescriptorSubTLV, 0)
	for p := 0; p < len(b); {
		stlv := NodeDescriptorSubTLV{}
		t := binary.BigEndian.Uint16(b[p : p+2])
		switch t {
		case 512:
		case 513:
		case 514:
		case 515:
		default:
			return nil, fmt.Errorf("invalid Node Descriptor Sub TLV type %d", t)
		}
		stlv.Type = t
		p += 2
		stlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		stlv.Value = make([]byte, stlv.Length)
		copy(stlv.Value, b[p:p+int(stlv.Length)])
		stlvs = append(stlvs, stlv)
		p += int(stlv.Length)
	}

	return stlvs, nil
}
