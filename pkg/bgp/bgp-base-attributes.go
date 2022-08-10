package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// BaseAttributes defines a structure holding BGP's basic, non nlri based attributes,
// codes for each can be found:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
type BaseAttributes struct {
	BaseAttrHash     string   `json:"base_attr_hash,omitempty"`
	Origin           string   `json:"origin,omitempty"`
	ASPath           []uint32 `json:"as_path,omitempty"`
	ASPathCount      int32    `json:"as_path_count,omitempty"`
	Nexthop          string   `json:"nexthop,omitempty"`
	MED              uint32   `json:"med,omitempty"`
	LocalPref        uint32   `json:"local_pref,omitempty"`
	IsAtomicAgg      bool     `json:"is_atomic_agg"`
	Aggregator       []byte   `json:"aggregator,omitempty"`
	CommunityList    []string `json:"community_list,omitempty"`
	OriginatorID     string   `json:"originator_id,omitempty"`
	ClusterList      string   `json:"cluster_list,omitempty"`
	ExtCommunityList []string `json:"ext_community_list,omitempty"`
	AS4Path          []uint32 `json:"as4_path,omitempty"`
	AS4PathCount     int32    `json:"as4_path_count,omitempty"`
	AS4Aggregator    []byte   `json:"as4_aggregator,omitempty"`
	// PMSITunnel
	TunnelEncapAttr []byte `json:"-"`
	// TraficEng
	// IPv6SpecExtCommunity
	// AIGP
	// PEDistinguisherLable
	LgCommunityList []string `json:"large_community_list,omitempty"`
	// SecPath
	// AttrSet
}

// UnmarshalBGPBaseAttributes discovers all present Base Attributes in BGP Update
// and instantiates BaseAttributes object
func UnmarshalBGPBaseAttributes(b []byte) (*BaseAttributes, error) {
	if glog.V(6) {
		glog.Infof("UnmarshalBGPBaseAttributes RAW: %+v", tools.MessageHex(b))
	}
	baseAttr := BaseAttributes{}
	for p := 0; p < len(b); {
		flag := b[p]
		p++
		t := b[p]
		p++
		var l uint16
		// Checking for Extened
		if flag&0x10 == 0x10 {
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			l = uint16(b[p])
			p++
		}
		switch t {
		case 1:
			baseAttr.Origin = unmarshalAttrOrigin(b[p : p+int(l)])
		case 2:
			baseAttr.ASPath = unmarshalAttrASPath(b[p : p+int(l)])
			baseAttr.ASPathCount = int32(len(baseAttr.ASPath))
		case 3:
			baseAttr.Nexthop = unmarshalAttrNextHop(b[p : p+int(l)])
		case 4:
			baseAttr.MED = unmarshalAttrMED(b[p : p+int(l)])
		case 5:
			baseAttr.LocalPref = unmarshalAttrLocalPref(b[p : p+int(l)])
		case 6:
			baseAttr.IsAtomicAgg = true
		case 7:
			baseAttr.Aggregator = unmarshalAttrAggregator(b[p : p+int(l)])
		case 8:
			baseAttr.CommunityList = unmarshalAttrCommunity(b[p : p+int(l)])
		case 9:
			baseAttr.OriginatorID = unmarshalAttrOriginatorID(b[p : p+int(l)])
		case 10:
			baseAttr.ClusterList = unmarshalAttrClusterList(b[p : p+int(l)])
		case 16:
			baseAttr.ExtCommunityList = unmarshalAttrExtCommunity(b[p : p+int(l)])
		case 17:
			baseAttr.AS4Path = unmarshalAttrAS4Path(b[p : p+int(l)])
			baseAttr.AS4PathCount = int32(len(baseAttr.AS4Path))
		case 18:
			baseAttr.AS4Aggregator = unmarshalAttrAS4Aggregator(b[p : p+int(l)])
		case 22:
		case 23:
			baseAttr.TunnelEncapAttr = make([]byte, l)
			copy(baseAttr.TunnelEncapAttr, b[p:p+int(l)])
		case 24:
		case 25:
		case 26:
		case 27:
		case 28:
		case 29:
		case 32:
			baseAttr.LgCommunityList = unmarshalAttrLgCommunity(b[p : p+int(l)])
		case 33:
		case 128:
		}
		p += int(l)
	}
	// Calculating hash of all recovered base attributes
	ba, err := json.Marshal(baseAttr)
	if err != nil {
		return nil, err
	}
	s := md5.Sum(ba)
	baseAttr.BaseAttrHash = hex.EncodeToString(s[:])

	return &baseAttr, nil
}

// unmarshalAttrOrigin returns the value of Origin attribute
func unmarshalAttrOrigin(b []byte) string {
	switch b[0] {
	case 0:
		return "igp"
	case 1:
		return "egp"
	case 2:
		return "incomplete"
	default:
		return ""
	}
}

// unmarshalAttrASPath returns a slice with a list of ASes
func unmarshalAttrASPath(b []byte) []uint32 {
	if len(b) == 0 {
		return nil
	}
	path := make([]uint32, 0)
	as4 := isASPath4(b)
	for p := 0; p < len(b); {
		// Skipping type
		p++
		// Length of path segment of type
		l := b[p]
		p++
		// Attempting to detect if 2 or 4 bytes AS is used
		for n := 0; n < int(l); n++ {
			if as4 {
				as := binary.BigEndian.Uint32(b[p : p+4])
				p += 4
				path = append(path, as)
			} else {
				as := binary.BigEndian.Uint16(b[p : p+2])
				p += 2
				path = append(path, uint32(as))
			}
		}
	}

	return path
}

func isASPath4(b []byte) bool {
	p := 0
	// Skipping type
	p++
	// Length of path segment in 2 or 4 bytes depending if AS2 or AS4 is used.
	l := int(b[p])
	p++
	// Check if next segment can be found with AS4
	if l*4 == len(b[p:]) {
		// Found last AS4 segment, confirmed AS4
		return true
	}
	// Check if next segment can be found with AS4
	if l*2 == len(b[p:]) {
		// Found last AS2 segment, confirmed AS2
		return false
	}
	// Check if next segment can be found with AS4
	if p+l*4 < len(b) {
		if b[p+l*4] == 0x1 || b[p+l*4] == 0x2 {
			// Found next AS4 segment, confirmed AS4
			return true
		}
	}
	// Check if next segment can be found with AS2
	if p+l*2 < len(b) {
		if b[p+l*2] == 0x1 || b[p+l*2] == 0x2 {
			// Found next AS2 segment, confirmed AS2
			return false
		}
	}
	// Should never reach here
	return false
}

// unmarshalAttrNextHop returns the value of Next Hop attribute
func unmarshalAttrNextHop(b []byte) string {
	if len(b) == 4 {
		return net.IP(b).To4().String()
	}
	return net.IP(b).To16().String()
}

// unmarshalAttrMED returns the value of MED attribute
func unmarshalAttrMED(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// unmarshalAttrLocalPref returns the value of LOCAL_PREF attribute
func unmarshalAttrLocalPref(b []byte) uint32 {
	if len(b) != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// unmarshalAttrAggregator returns the value of AGGREGATOR attribute
func unmarshalAttrAggregator(b []byte) []byte {
	agg := make([]byte, len(b))
	copy(agg, b)

	return agg
}

// getCommunity returns a slice of communities
func getCommunity(b []byte) []uint32 {
	comm := make([]uint32, 0)
	for p := 0; p < len(b); {
		c := binary.BigEndian.Uint32(b[p : p+4])
		p += 4
		comm = append(comm, c)
	}

	return comm
}

// unmarshalAttrCommunity returns the string with comma separated communities.
func unmarshalAttrCommunity(b []byte) []string {
	cs := getCommunity(b)
	s := make([]string, len(cs))
	for i, c := range cs {
		s[i] += strconv.Itoa(int((0xffff0000&c)>>16)) + ":" + strconv.Itoa(int(0xffff&c))
	}

	return s
}

// unmarshalAttrOriginatorID returns the value of ORIGINATOR_ID attribute
func unmarshalAttrOriginatorID(b []byte) string {
	if len(b) == 4 {
		return net.IP(b).To4().String()
	}

	return "invalid length"
}

// getClusterID returns a slice of Cluster IDs from Cluster List attribute
func getClusterID(b []byte) [][]byte {
	cl := make([][]byte, 0)
	i := 0
	for p := 0; p < len(b); {
		c := make([]byte, 4)
		copy(c, b[p:p+4])
		p += 4
		i++
		cl = append(cl, c)
	}

	return cl
}

// unmarshalAttrClusterList returns the string with comma separated communities.
func unmarshalAttrClusterList(b []byte) string {
	var clist string
	cl := getClusterID(b)
	for i, c := range cl {
		clist += net.IP(c).To4().String()
		if i < len(cl)-1 {
			clist += ", "
		}
	}

	return clist
}

//  unmarshalAttrExtCommunity returns a slice with all extended communities found in bgp update
func unmarshalAttrExtCommunity(b []byte) []string {
	ext, err := UnmarshalBGPExtCommunity(b)
	if err != nil {
		return nil
	}
	s := make([]string, len(ext))
	for i, c := range ext {
		s[i] += c.String()
	}

	return s
}

// unmarshalAttrLgCommunity returns a slice with all large communities found in bgp update
func unmarshalAttrLgCommunity(b []byte) []string {
	lg, err := UnmarshalBGPLgCommunity(b)
	if err != nil {
		return nil
	}
	s := make([]string, len(lg))
	for i, c := range lg {
		s[i] += c.String()
	}

	return s
}

// unmarshalAttrAS4Path returns a sequence of AS4 path segments
func unmarshalAttrAS4Path(b []byte) []uint32 {
	path := make([]uint32, 0)
	for p := 0; p < len(b); {
		// Skipping type
		p++
		// Length of path segment in 4 bytes
		l := b[p]
		p++
		for n := 0; n < int(l); n++ {
			as := binary.BigEndian.Uint32(b[p : p+4])
			p += 4
			path = append(path, as)
		}
	}

	return path
}

// getAttrAS4Aggregator returns the value of AS4 AGGREGATOR attribute
func unmarshalAttrAS4Aggregator(b []byte) []byte {
	agg := make([]byte, len(b))
	copy(agg, b)

	return agg
}
