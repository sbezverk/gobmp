package bgpls

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// TLV defines BGP-LS TLV object
// https://tools.ietf.org/html/rfc7752#section-3.3
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

func (ls *TLV) String() string {
	var s string
	switch ls.Type {

	// List of TLV to skip processing

	case 1173:
		break

	// List of TLV requireing additional processing

	case 258:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Link Local/Remote Identifiers)\n", ls.Type)
		lid := binary.BigEndian.Uint32(ls.Value)
		rid := binary.BigEndian.Uint32(ls.Value[4:])
		s += fmt.Sprintf("      Link Local: %d\n", lid)
		s += fmt.Sprintf("      Link Remote: %d\n", rid)
	case 263:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Multi-Topology Identifier)\n", ls.Type)
		mit, err := base.UnmarshalMultiTopologyIdentifierTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += mit.String()
	case 266:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Node MSD)\n", ls.Type)
		msd, err := base.UnmarshalNodeMSD(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += msd.String()
	case 267:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Link MSD)\n", ls.Type)
		msd, err := base.UnmarshalLinkMSD(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += msd.String()
	case 1026:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Node Name)\n", ls.Type)
		s += fmt.Sprintf("      Node Name: %s\n", string(ls.Value))
	case 1027:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IS-IS Area Identifier)\n", ls.Type)
		s += fmt.Sprintf("      IS-IS Area Identifier: %s\n", internal.MessageHex(ls.Value))
	case 1028:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv4 Router-ID of Local Node)\n", ls.Type)
		s += fmt.Sprintf("      IPv4 Router-ID of Local Node: %s\n", net.IP(ls.Value).To4().String())
	case 1029:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv6 Router-ID of Local Node)\n", ls.Type)
		s += fmt.Sprintf("      IPv6 Router-ID of Local Node: %s\n", net.IP(ls.Value).To16().String())
	case 1030:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv4 Router-ID of Remote Node)\n", ls.Type)
		s += fmt.Sprintf("      IPv4 Router-ID of Remote Node: %s\n", net.IP(ls.Value).To4().String())
	case 1031:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IPv6 Router-ID of Remote Node)\n", ls.Type)
		s += fmt.Sprintf("      IPv6 Router-ID of Remote Node: %s\n", net.IP(ls.Value).To16().String())
	case 1034:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Capabilities)\n", ls.Type)
		s += fmt.Sprintf("      SR Capabilities: %s\n", internal.MessageHex(ls.Value))
	case 1035:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Algorithm)\n", ls.Type)
		s += fmt.Sprintf("      SR Algorithm: %s\n", internal.MessageHex(ls.Value))
	case 1036:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SR Local Block)\n", ls.Type)
		s += fmt.Sprintf("      SR Local Block: %s\n", internal.MessageHex(ls.Value))
	case 1038:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Capabilities TLV)\n", ls.Type)
		cap, err := srv6.UnmarshalSRv6CapabilityTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += cap.String(2)
	case 1088:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Administrative group (color))\n", ls.Type)
		s += fmt.Sprintf("      Administrative group (color): %d\n", binary.BigEndian.Uint32(ls.Value))
	case 1089:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Maximum link bandwidth)\n", ls.Type)
		s += fmt.Sprintf("      Maximum link bandwidth: %d\n", binary.BigEndian.Uint32(ls.Value))
	case 1090:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Max. reservable link bandwidth)\n", ls.Type)
		s += fmt.Sprintf("      Max. reservable link bandwidth: %s\n", internal.MessageHex(ls.Value))
	case 1091:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Unreserved bandwidth)\n", ls.Type)
		s += fmt.Sprintf("      Unreserved bandwidth: %s\n", internal.MessageHex(ls.Value))
	case 1092:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (IGP Metric)\n", ls.Type)
		m := binary.BigEndian.Uint32(ls.Value)
		s += fmt.Sprintf("      IGP Metric: %d\n", m)
	case 1095:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (TE Default Metric)\n", ls.Type)
		s += fmt.Sprintf("      TE Default Metric: %s\n", internal.MessageHex(ls.Value))
	case 1099:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Adjacency Segment Identifier)\n", ls.Type)
		asid, err := sr.UnmarshalAdjacencySIDTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += asid.String()
	case 1106:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 End.X SID TLV)\n", ls.Type)
		endx, err := srv6.UnmarshalSRv6EndXSIDTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += endx.String(1)
	case 1155:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix Metric)\n", ls.Type)
		m := binary.BigEndian.Uint32(ls.Value)
		s += fmt.Sprintf("      Prefix Metric: %d\n", m)
	case 1158:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix SID)\n", ls.Type)
		psid, err := sr.UnmarshalPrefixSIDTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += psid.String()
	case 1162:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Locator TLV)\n", ls.Type)
		l, err := srv6.UnmarshalSRv6LocatorTLV(ls.Value)
		if err != nil {
			s += err.Error() + "\n"
			break
		}
		s += l.String(1)
	case 1170:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Prefix Attributes Flags)\n", ls.Type)
		s += fmt.Sprintf("      Flag: %s\n", internal.MessageHex(ls.Value))
	case 1171:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (Source Router-ID)\n", ls.Type)
		if ls.Length == 4 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(ls.Value).To4().String())
		} else if ls.Length == 16 {
			s += fmt.Sprintf("   Source Router-ID: %s\n", net.IP(ls.Value).To16().String())
		}
	case 1250:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Endpoint Function)\n", ls.Type)
		s += fmt.Sprintf("      Endpoint Behavior: %s\n", internal.MessageHex(ls.Value[:2]))
		s += fmt.Sprintf("      Flag: %02x\n", ls.Value[2])
		s += fmt.Sprintf("      Algorithm: %d\n", ls.Value[3])
	case 1251:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 Endpoint Function)\n", ls.Type)
		s += fmt.Sprintf("      Flag: %02x\n", ls.Value[0])
		s += fmt.Sprintf("      Weight: %d\n", ls.Value[1])
		s += fmt.Sprintf("      Peer AS Number: %d\n", binary.BigEndian.Uint32(ls.Value[4:8]))
		s += fmt.Sprintf("      Peer BGP Identifier: %s\n", internal.MessageHex(ls.Value[8:12]))
	case 1252:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d (SRv6 SID Structure)\n", ls.Type)
		s += fmt.Sprintf("      LB Length: %d\n", ls.Value[0])
		s += fmt.Sprintf("      LN Length: %d\n", ls.Value[1])
		s += fmt.Sprintf("      Function Length: %d\n", ls.Value[2])
		s += fmt.Sprintf("      Argument Length: %d\n", ls.Value[3])

	// Default BGP-LS TLV processing

	default:
		s += fmt.Sprintf("   BGP-LS TLV Type: %d\n", ls.Type)
		s += fmt.Sprintf("   BGP-LS TLV Length: %d\n", ls.Length)
		s += "      Value: "
		s += internal.MessageHex(ls.Value)
		s += "\n"
	}

	return s
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
