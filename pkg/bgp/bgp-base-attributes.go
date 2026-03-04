package bgp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/pmsi"
	"github.com/sbezverk/tools/sort"
)

// BaseAttributes defines a structure holding BGP's basic, non nlri based attributes,
// codes for each can be found:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
type BaseAttributes struct {
	BaseAttrHash     string           `json:"base_attr_hash,omitempty"`
	Origin           string           `json:"origin,omitempty"`
	ASPath           []uint32         `json:"as_path,omitempty"`
	ASPathCount      int32            `json:"as_path_count,omitempty"`
	Nexthop          string           `json:"nexthop,omitempty"`
	MED              uint32           `json:"med,omitempty"`
	LocalPref        uint32           `json:"local_pref,omitempty"`
	IsAtomicAgg      bool             `json:"is_atomic_agg"`
	Aggregator       []byte           `json:"aggregator,omitempty"`
	CommunityList    []string         `json:"community_list,omitempty"`
	OriginatorID     string           `json:"originator_id,omitempty"`
	ClusterList      string           `json:"cluster_list,omitempty"`
	ExtCommunityList []string         `json:"ext_community_list,omitempty"`
	AS4Path          []uint32         `json:"as4_path,omitempty"`
	AS4PathCount     int32            `json:"as4_path_count,omitempty"`
	AS4Aggregator    []byte           `json:"as4_aggregator,omitempty"`
	PMSITunnel       *pmsi.PMSITunnel `json:"pmsi_tunnel,omitempty"` // RFC 6514 PMSI Tunnel Attribute (Type 22)
	TunnelEncapAttr  []byte           `json:"-"`
	// TraficEng
	// IPv6SpecExtCommunity
	AIGP *AIGP `json:"aigp,omitempty"` // RFC 7311 AIGP Attribute (Type 26)
	// PEDistinguisherLable
	LgCommunityList []string      `json:"large_community_list,omitempty"`
	BGPPrefixSID    *BGPPrefixSID `json:"bgp_prefix_sid,omitempty"`
	// SecPath
	// AttrSet
}

func (ba *BaseAttributes) Equal(oba *BaseAttributes) (bool, []string) {
	equal := true
	diffs := make([]string, 0)

	if ba.Origin != oba.Origin {
		equal = false
		diffs = append(diffs, "origin mismatch: "+ba.Origin+" and "+oba.Origin)
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.ASPath), sort.SortMergeComparableSlice(oba.ASPath)) {
		equal = false
		diffs = append(diffs, "as_path mismatch")
	}
	if ba.ASPathCount != oba.ASPathCount {
		equal = false
		diffs = append(diffs, "as_path_count mismatch: "+strconv.Itoa(int(ba.ASPathCount))+" and "+strconv.Itoa(int(oba.ASPathCount)))
	}
	if ba.Nexthop != oba.Nexthop {
		equal = false
		diffs = append(diffs, "nexthop mismatch: "+ba.Nexthop+" and "+oba.Nexthop)
	}
	if ba.MED != oba.MED {
		equal = false
		diffs = append(diffs, "med mismatch: "+strconv.Itoa(int(ba.MED))+" and "+strconv.Itoa(int(oba.MED)))
	}
	if ba.LocalPref != oba.LocalPref {
		equal = false
		diffs = append(diffs, "local_pref mismatch: "+strconv.Itoa(int(ba.LocalPref))+" and "+strconv.Itoa(int(oba.LocalPref)))
	}
	if ba.IsAtomicAgg != oba.IsAtomicAgg {
		equal = false
		diffs = append(diffs, "is_atomic_agg mismatch: "+strconv.FormatBool(ba.IsAtomicAgg)+" and "+strconv.FormatBool(oba.IsAtomicAgg))
	}
	if !bytes.Equal(ba.Aggregator, oba.Aggregator) {
		equal = false
		diffs = append(diffs, "aggregator mismatch")
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.CommunityList), sort.SortMergeComparableSlice(oba.CommunityList)) {
		equal = false
		diffs = append(diffs, "community_list mismatch")
	}
	if ba.OriginatorID != oba.OriginatorID {
		equal = false
		diffs = append(diffs, "originator_id mismatch: "+ba.OriginatorID+" and "+oba.OriginatorID)
	}
	if ba.ClusterList != oba.ClusterList {
		equal = false
		diffs = append(diffs, "cluster_list mismatch: "+ba.ClusterList+" and "+oba.ClusterList)
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.ExtCommunityList), sort.SortMergeComparableSlice(oba.ExtCommunityList)) {
		equal = false
		diffs = append(diffs, "ext_community_list mismatch")
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.AS4Path), sort.SortMergeComparableSlice(oba.AS4Path)) {
		equal = false
		diffs = append(diffs, "as4_path mismatch")
	}
	if ba.AS4PathCount != oba.AS4PathCount {
		equal = false
		diffs = append(diffs, "as4_path_count mismatch: "+strconv.Itoa(int(ba.AS4PathCount))+" and "+strconv.Itoa(int(oba.AS4PathCount)))
	}
	if !bytes.Equal(ba.AS4Aggregator, oba.AS4Aggregator) {
		equal = false
		diffs = append(diffs, "as4_aggregator mismatch")
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.LgCommunityList), sort.SortMergeComparableSlice(oba.LgCommunityList)) {
		equal = false
		diffs = append(diffs, "large_community_list mismatch")
	}

	return equal, diffs

}

// UnmarshalBGPBaseAttributes discovers all present Base Attributes in BGP Update
// and instantiates BaseAttributes object. It is a convenience wrapper that parses
// the raw byte slice via UnmarshalBGPPathAttributes and then populates BaseAttributes.
func UnmarshalBGPBaseAttributes(b []byte) (*BaseAttributes, error) {
	attrs, baseAttrs, err := UnmarshalBGPPathAttributes(b)
	_ = attrs // raw slice not needed by this call-path
	return baseAttrs, err
}

// unmarshalBaseAttrsFromSlice populates a BaseAttributes struct from an already-parsed
// []PathAttribute slice, avoiding a second walk of the raw byte buffer.
func unmarshalBaseAttrsFromSlice(attrs []PathAttribute) (*BaseAttributes, error) {
	baseAttr := BaseAttributes{}
	for _, attr := range attrs {
		b := attr.Attribute
		switch attr.AttributeType {
		case 1:
			baseAttr.Origin = unmarshalAttrOrigin(b)
		case 2:
			var err error
			baseAttr.ASPath, err = unmarshalAttrASPath(b)
			if err != nil {
				return nil, err
			}
			baseAttr.ASPathCount = int32(len(baseAttr.ASPath))
		case 3:
			baseAttr.Nexthop = unmarshalAttrNextHop(b)
		case 4:
			baseAttr.MED = unmarshalAttrMED(b)
		case 5:
			baseAttr.LocalPref = unmarshalAttrLocalPref(b)
		case 6:
			baseAttr.IsAtomicAgg = true
		case 7:
			baseAttr.Aggregator = unmarshalAttrAggregator(b)
		case 8:
			baseAttr.CommunityList = unmarshalAttrCommunity(b)
		case 9:
			baseAttr.OriginatorID = unmarshalAttrOriginatorID(b)
		case 10:
			var err error
			baseAttr.ClusterList, err = unmarshalAttrClusterList(b)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal Cluster List attribute with error: %+v", err)
			}
		case 11:
			// DPA (deprecated) - RFC 6938
		case 12:
			// ADVERTISER (deprecated) - RFC 1863, RFC 6938
		case 13:
			// RCID_PATH / CLUSTER_ID (deprecated) - RFC 1863, RFC 6938
		case 14:
			// MP_REACH_NLRI - RFC 4760 (parsed separately in path attribute parser)
		case 15:
			// MP_UNREACH_NLRI - RFC 4760 (parsed separately in path attribute parser)
		case 16:
			baseAttr.ExtCommunityList = unmarshalAttrExtCommunity(b)
		case 17:
			baseAttr.AS4Path = unmarshalAttrAS4Path(b)
			baseAttr.AS4PathCount = int32(len(baseAttr.AS4Path))
		case 18:
			baseAttr.AS4Aggregator = unmarshalAttrAS4Aggregator(b)
		case 19:
			// SAFI Specific Attribute (SSA, deprecated)
		case 20:
			// Connector Attribute (deprecated) - RFC 6037
		case 21:
			// AS_PATHLIMIT (deprecated) - draft-ietf-idr-as-pathlimit
		case 22:
			// RFC 6514 PMSI Tunnel Attribute
			tunnel, err := pmsi.ParsePMSITunnel(b)
			if err != nil {
				glog.Errorf("failed to parse PMSI Tunnel attribute: %v", err)
			} else {
				baseAttr.PMSITunnel = tunnel
			}
		case 23:
			// Tunnel Encapsulation Attribute - RFC 9012
			baseAttr.TunnelEncapAttr = make([]byte, len(b))
			copy(baseAttr.TunnelEncapAttr, b)
		case 24:
			// Traffic Engineering - RFC 5543
		case 25:
			// IPv6 Address Specific Extended Community - RFC 5701
		case 26:
			// RFC 7311: AIGP Attribute
			aigp, err := UnmarshalAIGP(b)
			if err != nil {
				glog.Errorf("failed to unmarshal AIGP attribute with error: %+v", err)
			} else {
				baseAttr.AIGP = aigp
			}
		case 27:
			// PE Distinguisher Labels - RFC 6514
		case 28:
			// BGP Entropy Label Capability Attribute (deprecated) - RFC 6790, RFC 7447
		case 29:
			// BGP-LS Attribute - RFC 9552
		case 30:
			// Deprecated - RFC 8093
		case 31:
			// Deprecated - RFC 8093
		case 32:
			baseAttr.LgCommunityList = unmarshalAttrLgCommunity(b)
		case 33:
			// BGPsec_Path - RFC 8205
		case 34:
			// BGP Community Container Attribute (TEMPORARY) - draft-ietf-idr-wide-bgp-communities
		case 35:
			// Only to Customer (OTC) - RFC 9234
		case 36:
			// BGP Domain Path (D-PATH, TEMPORARY) - draft-ietf-bess-evpn-ipvpn-interworking
		case 37:
			// SFP attribute - RFC 9015
		case 38:
			// BFD Discriminator - RFC 9026
		case 39:
			// BGP Next Hop Dependent Characteristic (NHC, TEMPORARY) - draft-ietf-idr-nhc
		case 40:
			// RFC 8669: BGP Prefix-SID
			var err error
			baseAttr.BGPPrefixSID, err = UnmarshalBGPPrefixSID(b)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal BGP Prefix-SID attribute with error: %+v", err)
			}
		case 41:
			// BIER - RFC 9793
		case 42:
			// Edge Metadata Path Attribute (TEMPORARY) - draft-ietf-idr-5g-edge-service-metadata
		case 128:
			// ATTR_SET - RFC 6368
		}
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
func unmarshalAttrASPath(b []byte) ([]uint32, error) {
	if len(b) == 0 {
		return []uint32{}, nil
	}
	path := make([]uint32, 0)
	// Attempting to detect if AS4 is used in AS_PATH attribute, this call also validates
	// the attribute and returns error if invalid, no further guards needed in the loop below.
	as4, err := isASPath4(b)
	if err != nil {
		return nil, err
	}
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

	return path, nil
}

func isASPath4(b []byte) (bool, error) {
	p := 0
	// Skipping type
	if p+1 >= len(b) {
		return false, fmt.Errorf("invalid AS_PATH attribute, not enough bytes %d to read path segment type", len(b)-p)
	}
	p++
	// Length of path segment in 2 or 4 bytes depending if AS2 or AS4 is used.
	l := int(b[p])
	if p+1 >= len(b) {
		return false, fmt.Errorf("invalid AS_PATH attribute, not enough bytes %d to read path segment length", len(b)-p)
	}
	p++
	// Check if next segment can be found with AS4
	if l*4 == len(b[p:]) {
		// Found last AS4 segment, confirmed AS4
		return true, nil
	}
	// Check if next segment can be found with AS4
	if l*2 == len(b[p:]) {
		// Found last AS2 segment, confirmed AS2
		return false, nil
	}
	// Check if next segment can be found with AS4
	if p+l*4 < len(b) {
		if b[p+l*4] == 0x1 || b[p+l*4] == 0x2 {
			// Found next AS4 segment, confirmed AS4
			return true, nil
		}
	}
	// Check if next segment can be found with AS2
	if p+l*2 < len(b) {
		if b[p+l*2] == 0x1 || b[p+l*2] == 0x2 {
			// Found next AS2 segment, confirmed AS2
			return false, nil
		}
	}
	// Should never reach here
	return false, fmt.Errorf("invalid AS_PATH attribute, unable to determine AS path type")
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

// unmarshalAttrClusterList returns the string with comma separated communities.
func unmarshalAttrClusterList(b []byte) (string, error) {
	if len(b) == 0 {
		return "", nil
	}
	if len(b)%4 != 0 {
		return "", fmt.Errorf("invalid length expected multiple of 4 got %d", len(b))
	}
	parts := make([]string, len(b)/4)
	for i := 0; i < len(b); i += 4 {
		parts[i/4] = net.IP(b[i : i+4]).To4().String()
	}
	return strings.Join(parts, ", "), nil
}

// unmarshalAttrExtCommunity returns a slice with all extended communities found in bgp update
func unmarshalAttrExtCommunity(b []byte) []string {
	ext, err := UnmarshalBGPExtCommunity(b)
	if err != nil {
		return nil
	}
	s := make([]string, len(ext))
	for i, c := range ext {
		s[i] = c.String()
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
