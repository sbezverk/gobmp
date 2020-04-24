package bgpls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/tools"
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
	//	case 258:
	//		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Link Local/Remote Identifiers)\n", tlv.Type)
	//		lri, err := base.UnmarshalLocalRemoteIdentifierTLV(tlv.Value)
	//		if err != nil {
	//			s += err.Error() + "\n"
	//			break
	//		}
	//		s += lri.String()
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
		s += fmt.Sprintf("      IS-IS Area Identifier: %s\n", tools.MessageHex(tlv.Value))
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
		s += fmt.Sprintf("      SR Capabilities: %s\n", tools.MessageHex(tlv.Value))
	case 1035:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Algorithm)\n", tlv.Type)
		s += fmt.Sprintf("      SR Algorithm: %s\n", tools.MessageHex(tlv.Value))
	case 1036:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Local Block)\n", tlv.Type)
		s += fmt.Sprintf("      SR Local Block: %s\n", tools.MessageHex(tlv.Value))
	case 1038:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Capabilities TLV)\n", tlv.Type)
		cap, err := srv6.UnmarshalSRv6CapabilityTLV(tlv.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += cap.String()
	case 1088:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Administrative group (color))\n", tlv.Type)
		s += fmt.Sprintf("      Administrative group (color): %d\n", binary.BigEndian.Uint32(tlv.Value))
	case 1089:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Maximum link bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Maximum link bandwidth: %d\n", binary.BigEndian.Uint32(tlv.Value))
	case 1090:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Max. reservable link bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Max. reservable link bandwidth: %s\n", tools.MessageHex(tlv.Value))
	case 1091:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Unreserved bandwidth)\n", tlv.Type)
		s += fmt.Sprintf("      Unreserved bandwidth: %s\n", tools.MessageHex(tlv.Value))
	case 1095:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IGP Metric)\n", tlv.Type)
		m := binary.BigEndian.Uint32(tlv.Value)
		s += fmt.Sprintf("      IGP Metric: %d\n", m)
	case 1092:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (TE Default Metric)\n", tlv.Type)
		s += fmt.Sprintf("      TE Default Metric: %s\n", tools.MessageHex(tlv.Value))
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
		s += endx.String()
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
		s += l.String()
	case 1170:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix Attributes Flags)\n", tlv.Type)
		s += fmt.Sprintf("      Flag: %s\n", tools.MessageHex(tlv.Value))
	case 1171:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Source Router-ID)\n", tlv.Type)
		if tlv.Length == 4 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(tlv.Value).To4().String())
		} else if tlv.Length == 16 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(tlv.Value).To16().String())
		}
	case 1173:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Extended Administrative Group)\n", tlv.Type)
		s += fmt.Sprintf("      Color: %s\n", tools.MessageHex(tlv.Value))
	case 1250:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Endpoint Function)\n", tlv.Type)
		s += fmt.Sprintf("      Endpoint Behavior: %s\n", tools.MessageHex(tlv.Value[:2]))
		s += fmt.Sprintf("      Flag: %02x\n", tlv.Value[2])
		s += fmt.Sprintf("      Algorithm: %d\n", tlv.Value[3])
	case 1251:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 BGP Peer Node SID)\n", tlv.Type)
		s += fmt.Sprintf("      Flag: %02x\n", tlv.Value[0])
		s += fmt.Sprintf("      Weight: %d\n", tlv.Value[1])
		s += fmt.Sprintf("      Peer AS Number: %d\n", binary.BigEndian.Uint32(tlv.Value[4:8]))
		s += fmt.Sprintf("      Peer BGP Identifier: %s\n", tools.MessageHex(tlv.Value[8:12]))
	case 1252:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 SID Structure)\n", tlv.Type)
		s += fmt.Sprintf("      LB Length: %d\n", tlv.Value[0])
		s += fmt.Sprintf("      LN Length: %d\n", tlv.Value[1])
		s += fmt.Sprintf("      Function Length: %d\n", tlv.Value[2])
		s += fmt.Sprintf("      Argument Length: %d\n", tlv.Value[3])
	default:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d\n", tlv.Type)
		s += fmt.Sprintf("   BGP-LS TLV Length: %d\n", tlv.Length)
		s += "      Value: "
		s += tools.MessageHex(tlv.Value)
		s += "\n"
	}

	return s
}

// UnmarshalBGPLSTLV builds Collection of BGP-LS TLVs
func UnmarshalBGPLSTLV(b []byte) ([]TLV, error) {
	glog.V(6).Infof("BGPLSTLV Raw: %s", tools.MessageHex(b))
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

	buildAttributeMap(b)

	return lstlvs, nil
}

func buildAttributeMap(b []byte) map[uint16][]TLV {
	m := make(map[uint16][]TLV)
	for p := 0; p < len(b); {
		lstlv := TLV{}
		lstlv.Type = binary.BigEndian.Uint16(b[p : p+2])
		lstlvs, ok := m[lstlv.Type]
		if !ok {
			// If type of attribute is not in the map, allocating empty slice
			lstlvs = make([]TLV, 0)
		}
		p += 2
		lstlv.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		lstlv.Value = make([]byte, lstlv.Length)
		// TODO add check for Offset not exceeding slice's capacity
		copy(lstlv.Value, b[p:p+int(lstlv.Length)])
		p += int(lstlv.Length)
		lstlvs = append(lstlvs, lstlv)
		m[lstlv.Type] = lstlvs
	}

	ms, _ := json.Marshal(m)
	glog.Infof("><SB> Resulted map: %s", string(ms))

	return m
}
