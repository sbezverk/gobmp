package bgpls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// TLV defines BGP-LS TLV object
// https://tootlv.ietf.org/html/rfc7752#section-3.3
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (tlv *TLV) String() string {
	var s string
	switch tlv.Type {
	case 258:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Link Local/Remote Identifiers)\n", tlv.Type)
		lri, err := base.UnmarshalLocalRemoteIdentifierTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += lri.String()
	case 263:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Multi-Topology Identifier)\n", tlv.Type)
		mit, err := base.UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += mit.String()
	case 266:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Node MSD)\n", tlv.Type)
		msd, err := base.UnmarshalNodeMSD(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += msd.String()
	case 267:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Link MSD)\n", tlv.Type)
		msd, err := base.UnmarshalLinkMSD(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += msd.String()
	case 1026:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Node Name)\n", tlv.Type)
		s += fmt.Sprintf("      Node Name: %s\n", string(tlv.Value))
	case 1027:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IS-IS Area Identifier)\n", tlv.Type)
		s += fmt.Sprintf("      IS-IS Area Identifier: %s\n", internal.MessageHex(tlv.Value))
	case 1028:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv4 Router-ID of Local Node)\n", tlv.Type)
		s += fmt.Sprintf("      IPv4 Router-ID of Local Node: %s\n", net.IP(tlv.Value).To4().String())
	case 1029:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv6 Router-ID of Local Node)\n", tlv.Type)
		s += fmt.Sprintf("      IPv6 Router-ID of Local Node: %s\n", net.IP(tlv.Value).To16().String())
	case 1030:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv4 Router-ID of Remote Node)\n", tlv.Type)
		s += fmt.Sprintf("      IPv4 Router-ID of Remote Node: %s\n", net.IP(tlv.Value).To4().String())
	case 1031:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv6 Router-ID of Remote Node)\n", tlv.Type)
		s += fmt.Sprintf("      IPv6 Router-ID of Remote Node: %s\n", net.IP(tlv.Value).To16().String())
	case 1034:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Capabilities)\n", tlv.Type)
		s += fmt.Sprintf("      SR Capabilities: %s\n", internal.MessageHex(tlv.Value))
	case 1035:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Algorithm)\n", tlv.Type)
		s += fmt.Sprintf("      SR Algorithm: %s\n", internal.MessageHex(tlv.Value))
	case 1036:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Local Block)\n", tlv.Type)
		s += fmt.Sprintf("      SR Local Block: %s\n", internal.MessageHex(tlv.Value))
	case 1038:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Capabilities TLV)\n", tlv.Type)
		cap, err := srv6.UnmarshalSRv6CapabilityTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += cap.String(2)
	case 1088:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Administrative group (color))\n", tlv.Type)
		s += fmt.Sprintf("      Administrative group (color): %d\n", binary.BigEndian.Uint32(tlv.Value))
	case 1089:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Maximum link bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Maximum link bandwidth: %d\n", binary.BigEndian.Uint32(tlv.Value))
	case 1090:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Max. reservable link bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Max. reservable link bandwidth: %s\n", internal.MessageHex(tlv.Value))
	case 1091:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Unreserved bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Unreserved bandwidth: %s\n", internal.MessageHex(tlv.Value))
	case 1092:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IGP Metric)\n", tlv.Type)
		m := binary.BigEndian.Uint32(tlv.Value)
		s += fmt.Sprintf("      IGP Metric: %d\n", m)
	case 1095:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (TE Default Metric)\n", tlv.Type)
		s += fmt.Sprintf("      TE Default Metric: %s\n", internal.MessageHex(tlv.Value))
	case 1099:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Adjacency Segment Identifier)\n", tlv.Type)
		asid, err := sr.UnmarshalAdjacencySIDTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += asid.String()
	case 1106:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 End.X SID TLV)\n", tlv.Type)
		endx, err := srv6.UnmarshalSRv6EndXSIDTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += endx.String(1)
	case 1155:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix Metric)\n", tlv.Type)
		m := binary.BigEndian.Uint32(tlv.Value)
		s += fmt.Sprintf("      Prefix Metric: %d\n", m)
	case 1158:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix SID)\n", tlv.Type)
		psid, err := sr.UnmarshalPrefixSIDTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += psid.String()
	case 1162:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Locator TLV)\n", tlv.Type)
		l, err := srv6.UnmarshalSRv6LocatorTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += l.String(1)
	case 1170:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix Attributes Flags)\n", tlv.Type)
		s += fmt.Sprintf("      Flag: %s\n", internal.MessageHex(tlv.Value))
	case 1171:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Source Router-ID)\n", tlv.Type)
		if tlv.Length == 4 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(tlv.Value).To4().String())
		} else if tlv.Length == 16 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(tlv.Value).To16().String())
		}
	case 1173:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Extended Administrative Group)\n", tlv.Type)
		s += fmt.Sprintf("      Color: %s\n", internal.MessageHex(tlv.Value))
	case 1250:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Endpoint Function)\n", tlv.Type)
		s += fmt.Sprintf("      Endpoint Behavior: %s\n", internal.MessageHex(tlv.Value[:2]))
		s += fmt.Sprintf("      Flag: %02x\n", tlv.Value[2])
		s += fmt.Sprintf("      Algorithm: %d\n", tlv.Value[3])
	case 1251:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Endpoint Function)\n", tlv.Type)
		s += fmt.Sprintf("      Flag: %02x\n", tlv.Value[0])
		s += fmt.Sprintf("      Weight: %d\n", tlv.Value[1])
		s += fmt.Sprintf("      Peer AS Number: %d\n", binary.BigEndian.Uint32(tlv.Value[4:8]))
		s += fmt.Sprintf("      Peer BGP Identifier: %s\n", internal.MessageHex(tlv.Value[8:12]))
	case 1252:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 SID Structure)\n", tlv.Type)
		s += fmt.Sprintf("      LB Length: %d\n", tlv.Value[0])
		s += fmt.Sprintf("      LN Length: %d\n", tlv.Value[1])
		s += fmt.Sprintf("      Function Length: %d\n", tlv.Value[2])
		s += fmt.Sprintf("      Argument Length: %d\n", tlv.Value[3])

	// Default BGP-LS TLV processing

	default:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d\n", tlv.Type)
		s += fmt.Sprintf("   BGP-LS TLV Length: %d\n", tlv.Length)
		s += "      Value: "
		s += internal.MessageHex(tlv.Value)
		s += "\n"
	}

	return s
}

// func (tlv *LinkDescriptorTLV) String() string {
// 	var s string
// 	switch tlv.Type {
// 	case 258:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (Link Local/Remote Identifiers)\n", tlv.Type)
// 		lri, err := UnmarshalLocalRemoteIdentifierTLV(tlv.Value)
// 		if err != nil {
// 			s += err.Error() + "\n"
// 			break
// 		}
// 		s += lri.String()
// 	case 259:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv4 interface address)\n", tlv.Type)
// 		s += fmt.Sprintf("      IPv4 interface address: %s\n", net.IP(tlv.Value).To4().String())
// 	case 260:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv4 neighbor address)\n", tlv.Type)
// 		s += fmt.Sprintf("      IPv4 neighbor address: %s\n", net.IP(tlv.Value).To4().String())
// 	case 261:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv6 interface address)\n", tlv.Type)
// 		s += fmt.Sprintf("      IPv6 interface address: %s\n", net.IP(tlv.Value).To16().String())
// 	case 262:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (IPv6 neighbor address)\n", tlv.Type)
// 		s += fmt.Sprintf("      IPv6 neighbor address: %s\n", net.IP(tlv.Value).To16().String())
// 	case 263:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d (Multi-Topology Identifier)\n", tlv.Type)
// 		mit, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
// 		if err != nil {
// 			s += err.Error() + "\n"
// 			break
// 		}
// 		s += mit.String()
// 	default:
// 		s += fmt.Sprintf("   Link Descriptor TLV Type: %d\n", tlv.Type)
// 		s += fmt.Sprintf("   Link Descriptor TLV Length: %d\n", tlv.Length)
// 		s += "      Value: "
// 		s += internal.MessageHex(tlv.Value)
// 		s += "\n"
// 	}

// 	return s
// }

// case 259:
// 	jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv4 interface address\","))...)
// 	jsonData = append(jsonData, []byte("\"ipv4InterfaceAddress\":")...)
// 	jsonData = append(jsonData, internal.RawBytesToJSON(ltlv.Value)...)
// case 260:
// 	jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv4 neighbor address\","))...)
// 	jsonData = append(jsonData, []byte("\"ipv4NeighborAddress\":")...)
// 	jsonData = append(jsonData, internal.RawBytesToJSON(ltlv.Value)...)
// case 261:
// 	jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv6 interface address\","))...)
// 	jsonData = append(jsonData, []byte("\"ipv6InterfaceAddress\":")...)
// 	jsonData = append(jsonData, internal.RawBytesToJSON(ltlv.Value)...)
// case 262:
// 	jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv6 neighbor address\","))...)
// 	jsonData = append(jsonData, []byte("\"ipv6NeighborAddress\":")...)
// 	jsonData = append(jsonData, internal.RawBytesToJSON(ltlv.Value)...)

// MarshalJSON defines a method to Marshal BGP-LS TLV object into JSON format
func (tlv *TLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	var b []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", tlv.Type))...)
	jsonData = append(jsonData, []byte("\"Description\":")...)
	switch tlv.Type {
	case 258:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Local/Remote Identifiers\","))...)
		jsonData = append(jsonData, []byte("\"identifiersLocalRemote\":")...)
		lri, err := base.UnmarshalLocalRemoteIdentifierTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(lri)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 263:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Multi-Topology Identifier\","))...)
		jsonData = append(jsonData, []byte("\"multiTopologyIdentifier\":")...)
		mit, err := base.UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(mit)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 266:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Node MSD\","))...)
		jsonData = append(jsonData, []byte("\"nodeMSD\":")...)
		msd, err := base.UnmarshalNodeMSD(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(msd)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 267:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Link MSD\","))...)
		jsonData = append(jsonData, []byte("\"linkMSD\":")...)
		msd, err := base.UnmarshalLinkMSD(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(msd)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 1026:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Node Name\","))...)
		jsonData = append(jsonData, []byte("\"nodeName\":")...)
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"%s\"", string(tlv.Value)))...)
	case 1027:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IS-IS Area Identifier\","))...)
		jsonData = append(jsonData, []byte("\"isisAreaID\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1028:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv4 Router-ID of Local Node\","))...)
		jsonData = append(jsonData, []byte("\"localNodeIPv4RID\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1029:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv6 Router-ID of Local Node\","))...)
		jsonData = append(jsonData, []byte("\"localNodeIPv6RID\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1030:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv4 Router-ID of Remote Node\","))...)
		jsonData = append(jsonData, []byte("\"remoteNodeIPv4RID\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1031:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"IPv6 Router-ID of Remote Node\","))...)
		jsonData = append(jsonData, []byte("\"remoteNodeIPv6RID\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1034:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"SR Capabilities\","))...)
		jsonData = append(jsonData, []byte("\"srCapabilities\":")...)
		cap, err := sr.UnmarshalSRCapabilityTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(cap)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 1035:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"SR Algorithm\","))...)
		jsonData = append(jsonData, []byte("\"srAlgorithm\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	case 1036:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"SR Local Block\","))...)
		jsonData = append(jsonData, []byte("\"srLocalBlock\":")...)
		lb, err := sr.UnmarshalSRLocalBlockTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(lb)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	case 1038:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"SRv6 Capabilities\","))...)
		jsonData = append(jsonData, []byte("\"srv6Capabilities\":")...)
		cap, err := srv6.UnmarshalSRv6CapabilityTLV(tlv.Value)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(cap)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
	default:
		jsonData = append(jsonData, []byte(fmt.Sprintf("\"Unknown BGP-LS TLV\","))...)
		jsonData = append(jsonData, []byte("\"Value\":")...)
		jsonData = append(jsonData, internal.RawBytesToJSON(tlv.Value)...)
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPLSTLV builds Collection of BGP-LS TLVs
func UnmarshalBGPLSTLV(b []byte) ([]TLV, error) {
	glog.V(6).Infof("BGPLSTLV Raw: %s", internal.MessageHex(b))
	lstlvs := make([]TLV, 0)
	for p := 0; p < len(b); {
		lstlv := TLV{}
		lstlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		lstlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		lstlv.Value = make([]byte, lstlv.Length)
		copy(lstlv.Value, b[p:p+int(lstlv.Length)])
		p += int(lstlv.Length)
		lstlvs = append(lstlvs, lstlv)
	}

	return lstlvs, nil
}
