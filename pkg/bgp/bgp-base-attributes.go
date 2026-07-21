package bgp

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/pmsi"
	"github.com/sbezverk/gobmp/pkg/tunnel"
	"github.com/sbezverk/tools/sort"
)

// ASPathSegment represents a single segment of an AS_PATH attribute, which can be one of four types.
// Preserving the segment structure allows for more detailed analysis of the AS_PATH, including the ability to distinguish between AS_SET and AS_SEQUENCE segments, as well as handling of confederation segments.
// Used in ASPA validation logic.
type ASPathSegment struct {
	Type uint8    `json:"type"` // 1 AS_SET, 2 AS_SEQUENCE, 3 AS_CONFED_SEQUENCE, 4 AS_CONFED_SET
	ASNs []uint32 `json:"asns"`
}

// BaseAttributes defines a structure holding BGP's basic, non nlri based attributes,
// codes for each can be found:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
type BaseAttributes struct {
	BaseAttrHash   string          `json:"base_attr_hash,omitempty"`
	Origin         string          `json:"origin,omitempty"`
	ASPath         []uint32        `json:"as_path,omitempty"`
	ASPathCount    int32           `json:"as_path_count,omitempty"`
	ASPathSegments []ASPathSegment `json:"as_path_segments,omitempty"`
	Nexthop        string          `json:"nexthop,omitempty"`
	MED            uint32          `json:"med,omitempty"`
	LocalPref      uint32          `json:"local_pref,omitempty"`
	IsAtomicAgg    bool            `json:"is_atomic_agg"`
	Aggregator     []byte          `json:"aggregator,omitempty"`
	CommunityList  []string        `json:"community_list,omitempty"`
	// WellKnownCommunityList holds IANA symbolic names for any well-known
	// communities present in CommunityList (RFC 1997 and related).
	WellKnownCommunityList []string         `json:"well_known_community_list,omitempty"`
	OriginatorID           string           `json:"originator_id,omitempty"`
	ClusterList            string           `json:"cluster_list,omitempty"`
	ExtCommunityList       []string         `json:"ext_community_list,omitempty"`
	AS4Path                []uint32         `json:"as4_path,omitempty"`
	AS4PathCount           int32            `json:"as4_path_count,omitempty"`
	AS4Aggregator          []byte           `json:"as4_aggregator,omitempty"`
	PMSITunnel             *pmsi.PMSITunnel `json:"pmsi_tunnel,omitempty"` // RFC 6514 PMSI Tunnel Attribute (Type 22)
	// TunnelEncapAttr retains the raw RFC 9012 Tunnel Encapsulation Attribute
	// (path attribute type 23) bytes. Exposed in JSON so downstream consumers
	// can recover the original payload when UnmarshalTunnelEncapsulation
	// rejects the encoding and TunnelEncap is left nil. Also consumed in-process
	// by the SR Policy decoder in pkg/message/srpolicy.go (RFC 9256 view).
	TunnelEncapAttr []byte `json:"tunnel_encap_attr,omitempty"`
	// TunnelEncap is the decoded RFC 9012 Tunnel Encapsulation Attribute (Type 23).
	TunnelEncap *tunnel.TunnelEncapsulation `json:"tunnel_encap,omitempty"`
	// TunnelEncapMalformed is set when path attribute 23 was present on the wire
	// but UnmarshalTunnelEncapsulation rejected it. Lets downstream consumers
	// distinguish "attribute absent" from "attribute present but undecodable".
	TunnelEncapMalformed bool `json:"tunnel_encap_malformed,omitempty"`
	// TraficEng
	IPv6ExtCommunityList []string `json:"ipv6_ext_community_list,omitempty"` // RFC 5701
	AIGP                 *AIGP    `json:"aigp,omitempty"`                    // RFC 7311 AIGP Attribute (Type 26)
	// PEDistinguisherLable
	LgCommunityList []string      `json:"large_community_list,omitempty"`
	BGPPrefixSID    *BGPPrefixSID `json:"bgp_prefix_sid,omitempty"`
	OTC             uint32        `json:"otc,omitempty"` // RFC 9234 Only to Customer (OTC) Attribute (Type 35)
	// SecPath
	AttrSet *AttrSet `json:"attr_set,omitempty"` // RFC 6368 ATTR_SET Attribute (Type 128)
	// UnknownAttributes preserves any path attribute whose Type code is not
	// recognised by this parser. RFC 4271 §5 requires speakers to forward
	// transitive unrecognised attributes with the Partial bit set; a passive
	// BMP collector does not forward, but exposing the raw bytes lets
	// downstream consumers see attributes the collector does not yet decode
	// instead of silently dropping them.
	UnknownAttributes []UnknownPathAttribute `json:"unknown_attributes,omitempty"`

	// bgplsParsed memoizes the parsed BGP-LS Attribute (path attribute 29) so
	// repeated GetBGPLSAttribute calls reuse a single allocation. Eager
	// validation on receipt uses a non-allocating walk; this cache is populated
	// on the first detailed decode requested by a producer.
	bgplsParsed *bgpls.NLRI `json:"-"`
}

// UnknownPathAttribute is the raw form of a BGP path attribute whose Type
// code is not recognised by unmarshalBaseAttrsFromSlice. Flags is the full
// flags byte (RFC 4271 §4.3 — Optional (0x80)/Transitive (0x40)/Partial (0x20)/Extended Length (0x10)
// occupy the high nibble; low nibble bits 3-0 are reserved and MUST be zero).
type UnknownPathAttribute struct {
	Type  uint8  `json:"type"`
	Flags uint8  `json:"flags"`
	Value []byte `json:"value,omitempty"`
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
	if len(ba.ASPathSegments) != 0 {
		if len(ba.ASPathSegments) < len(oba.ASPathSegments) {
			equal = false
			diffs = append(diffs, "as_path_segments mismatch: additional segment in second BaseAttributes")
		}
		for i, seg := range ba.ASPathSegments {
			if i >= len(oba.ASPathSegments) {
				equal = false
				diffs = append(diffs, "as_path_segments mismatch: additional segment in first BaseAttributes")
				break
			}
			oseg := oba.ASPathSegments[i]
			if seg.Type != oseg.Type {
				equal = false
				diffs = append(diffs, fmt.Sprintf("as_path_segments[%d] type mismatch: %d and %d", i, seg.Type, oseg.Type))
			}
			if len(seg.ASNs) != len(oseg.ASNs) {
				equal = false
				diffs = append(diffs, fmt.Sprintf("as_path_segments[%d] length mismatch: %d and %d", i, len(seg.ASNs), len(oseg.ASNs)))
			}
			switch seg.Type {
			case 1, 4: // AS_SET or AS_CONFED_SET
				for _, asn := range seg.ASNs {
					if !slices.Contains(oseg.ASNs, asn) {
						equal = false
						diffs = append(diffs, fmt.Sprintf("as_path_segments[%d] ASNs mismatch: %v and %v", i, seg.ASNs, oseg.ASNs))
						break
					}
				}
			case 2, 3: // AS_SEQUENCE or AS_CONFED_SEQUENCE
				if !reflect.DeepEqual(seg.ASNs, oseg.ASNs) {
					equal = false
					diffs = append(diffs, fmt.Sprintf("as_path_segments[%d] ASNs mismatch: %v and %v", i, seg.ASNs, oseg.ASNs))
				}
			}
		}
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
	if !bytes.Equal(ba.TunnelEncapAttr, oba.TunnelEncapAttr) {
		equal = false
		diffs = append(diffs, "tunnel_encap_attr mismatch")
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.LgCommunityList), sort.SortMergeComparableSlice(oba.LgCommunityList)) {
		equal = false
		diffs = append(diffs, "large_community_list mismatch")
	}
	if !reflect.DeepEqual(sort.SortMergeComparableSlice(ba.IPv6ExtCommunityList), sort.SortMergeComparableSlice(oba.IPv6ExtCommunityList)) {
		equal = false
		diffs = append(diffs, "ipv6_ext_community_list mismatch")
	}
	if ba.OTC != oba.OTC {
		equal = false
		diffs = append(diffs, "otc mismatch: "+strconv.FormatUint(uint64(ba.OTC), 10)+" and "+strconv.FormatUint(uint64(oba.OTC), 10))
	}
	if asEqual, asDiffs := ba.AttrSet.Equal(oba.AttrSet); !asEqual {
		equal = false
		diffs = append(diffs, asDiffs...)
	}
	if !reflect.DeepEqual(ba.TunnelEncap, oba.TunnelEncap) {
		equal = false
		diffs = append(diffs, "tunnel_encap mismatch")
	}
	if ba.TunnelEncapMalformed != oba.TunnelEncapMalformed {
		equal = false
		diffs = append(diffs, "tunnel_encap_malformed mismatch: "+strconv.FormatBool(ba.TunnelEncapMalformed)+" and "+strconv.FormatBool(oba.TunnelEncapMalformed))
	}
	if !equalUnknownAttributes(ba.UnknownAttributes, oba.UnknownAttributes) {
		equal = false
		diffs = append(diffs, "unknown_attributes mismatch")
	}

	return equal, diffs

}

// equalUnknownAttributes compares two unknown-attribute slices semantically.
// reflect.DeepEqual is unsuitable here because it treats a nil slice as distinct
// from an empty slice (e.g. a JSON-decoded "unknown_attributes":[] versus a
// parser-produced nil), and likewise treats a nil Value as distinct from an
// empty []byte{}. Both pairs represent the same thing, so length, Type, Flags
// and bytes.Equal on Value are compared element-wise instead.
func equalUnknownAttributes(a, b []UnknownPathAttribute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Flags != b[i].Flags {
			return false
		}
		if !bytes.Equal(a[i].Value, b[i].Value) {
			return false
		}
	}
	return true
}

// UnmarshalBGPBaseAttributes discovers all present Base Attributes in a BGP
// Update and instantiates a BaseAttributes object. AS_PATH width is inferred
// by heuristic; use UnmarshalBGPBaseAttributesWithAS4Hint when the caller has
// an authoritative indicator.
func UnmarshalBGPBaseAttributes(b []byte) (*BaseAttributes, error) {
	_, baseAttrs, err := unmarshalBGPPathAttributes(b, nil)
	return baseAttrs, err
}

// UnmarshalBGPBaseAttributesWithAS4Hint is UnmarshalBGPBaseAttributes with an
// authoritative 4-byte-ASN indicator (typically PeerHeader.Is4ByteASN() per
// RFC 7854 §4.2, i.e. !A): true = 4-byte, false = 2-byte. Do not pass the
// raw A bit.
func UnmarshalBGPBaseAttributesWithAS4Hint(b []byte, as4 bool) (*BaseAttributes, error) {
	_, baseAttrs, err := unmarshalBGPPathAttributes(b, &as4)
	return baseAttrs, err
}

// unmarshalBaseAttrsFromSlice populates a BaseAttributes struct from an already-parsed
// []PathAttribute slice, avoiding a second walk of the raw byte buffer.
// as4hint, when non-nil, is the derived 4-byte-ASN indicator (Is4ByteASN() = !A per
// RFC 7854 §4.2): true = 4-byte, false = 2-byte. Overrides the AS_PATH width heuristic.
func unmarshalBaseAttrsFromSlice(attrs []PathAttribute, as4hint *bool) (*BaseAttributes, error) {
	baseAttr := BaseAttributes{}
	for _, attr := range attrs {
		b := attr.Attribute
		switch attr.AttributeType {
		case 1:
			baseAttr.Origin = unmarshalAttrOrigin(b)
		case 2:
			var err error
			var segments []ASPathSegment
			segments, err = unmarshalASPathSegments(b, as4hint)
			if err != nil {
				return nil, err
			}
			baseAttr.ASPathSegments = segments
			baseAttr.ASPath = buildASPathFromSegments(segments)
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
			baseAttr.WellKnownCommunityList = unmarshalWellKnownCommunity(b)
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
			// Tunnel Encapsulation Attribute - RFC 9012.
			// Retain the raw bytes for the SR Policy consumer in
			// pkg/message/srpolicy.go (it decodes RFC 9256 SR Policy TLVs from
			// the same payload), and additionally publish a decoded view via
			// TunnelEncap so generic consumers receive the parsed tunnel TLVs
			// without re-implementing the wire format.
			baseAttr.TunnelEncapAttr = make([]byte, len(b))
			copy(baseAttr.TunnelEncapAttr, b)
			te, err := tunnel.UnmarshalTunnelEncapsulation(b)
			if err != nil {
				glog.Errorf("failed to parse Tunnel Encapsulation attribute (path attribute type 23) per RFC 9012: %v", err)
				baseAttr.TunnelEncapMalformed = true
			} else {
				baseAttr.TunnelEncap = te
			}
		case 24:
			// Traffic Engineering - RFC 5543
		case 25:
			// IPv6 Address Specific Extended Community - RFC 5701
			baseAttr.IPv6ExtCommunityList = unmarshalAttrIPv6ExtCommunity(b)
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
			// BGP-LS Attribute - RFC 9552 §5.3.
			// Eagerly validate the TLV stream structure on receipt so a
			// malformed attribute is detected and logged at a single, central
			// site. Detailed per-TLV decoding is deferred to GetBGPLSAttribute,
			// invoked by message producers when a Link-State NLRI is emitted;
			// that call returns the same parse error and the producers skip
			// the BGP-LS-derived fields, so a malformed attribute does not
			// surface in published messages — the Attribute Discard outcome
			// required by RFC 7606 §3 / RFC 9552 §5.3 from a consumer's
			// perspective. The raw bytes remain in PathAttributes for
			// forensics; we do not mutate the slice here.
			if err := bgpls.ValidateBGPLSTLV(b); err != nil {
				glog.Errorf("malformed BGP-LS Attribute (path attribute type 29); content will be skipped in emitted messages per RFC 7606 §3 / RFC 9552 §5.3: %v", err)
			}
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
			baseAttr.OTC = unmarshalAttrOTC(b)
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
				baseAttr.BGPPrefixSID = nil
				glog.Errorf("failed to unmarshal BGP Prefix-SID attribute with error: %+v", err)
			}
		case 41:
			// BIER - RFC 9793
		case 42:
			// Edge Metadata Path Attribute (TEMPORARY) - draft-ietf-idr-5g-edge-service-metadata
		case 128:
			// ATTR_SET - RFC 6368
			attrSet, err := UnmarshalAttrSet(b)
			if err != nil {
				glog.Errorf("failed to unmarshal ATTR_SET attribute: %v", err)
			} else {
				baseAttr.AttrSet = attrSet
			}
		default:
			// Capture every unrecognised path attribute (any flag combination)
			// so downstream consumers see attributes the collector cannot
			// decode instead of having them silently disappear from the JSON
			// output. gobmp is a passive observer, so the RFC 4271 §5
			// Optional/Transitive forwarding distinction is not applied here;
			// the full flags byte is preserved on UnknownPathAttribute so
			// consumers can apply their own policy.
			// b aliases the fresh per-attribute buffer allocated in
			// unmarshalRawPathAttributes, so no extra copy is needed.
			ua := UnknownPathAttribute{
				Type:  attr.AttributeType,
				Flags: attr.AttributeTypeFlags,
			}
			if len(b) > 0 {
				ua.Value = b
			}
			baseAttr.UnknownAttributes = append(baseAttr.UnknownAttributes, ua)
		}
	}
	// Hash the raw attribute bytes directly instead of marshaling to JSON
	h := md5.New()
	for _, attr := range attrs {
		h.Write(attr.Attribute)
	}
	var digest [md5.Size]byte
	baseAttr.BaseAttrHash = hex.EncodeToString(h.Sum(digest[:0]))

	return &baseAttr, nil
}

// unmarshalAttrOrigin returns the value of Origin attribute
func unmarshalAttrOrigin(b []byte) string {
	if len(b) == 0 {
		return ""
	}
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

func buildASPathFromSegments(segments []ASPathSegment) []uint32 {
	path := make([]uint32, 0)
	for _, seg := range segments {
		path = append(path, seg.ASNs...)
	}
	return path
}

// unmarshalASPAthSegments returns a slice of ASPathSegment structs, preserving the segment structure of the AS_PATH attribute.
func unmarshalASPathSegments(b []byte, as4hint *bool) ([]ASPathSegment, error) {
	if len(b) == 0 {
		return []ASPathSegment{}, nil
	}
	segments := make([]ASPathSegment, 0)
	var as4 bool
	if as4hint != nil {
		as4 = *as4hint
	} else {
		var err error
		as4, err = isASPath4(b)
		if err != nil {
			return nil, err
		}
	}
	asSize := 2
	if as4 {
		asSize = 4
	}
	for p := 0; p < len(b); {
		segType := b[p]
		if segType < 0x01 || segType > 0x04 {
			return nil, fmt.Errorf("AS_PATH attribute invalid segment type 0x%02x at offset %d", segType, p)
		}
		p++
		if p+1 > len(b) {
			return nil, fmt.Errorf("AS_PATH attribute truncated: cannot read segment length at offset %d", p)
		}
		l := int(b[p])
		p++
		if p+l*asSize > len(b) {
			return nil, fmt.Errorf("AS_PATH attribute truncated: segment at offset %d claims %d ASes (%d bytes) but only %d bytes remain",
				p, l, l*asSize, len(b)-p)
		}
		asns := make([]uint32, 0, l)
		for n := 0; n < l; n++ {
			if as4 {
				asns = append(asns, binary.BigEndian.Uint32(b[p:p+4]))
				p += 4
			} else {
				asns = append(asns, uint32(binary.BigEndian.Uint16(b[p:p+2])))
				p += 2
			}
		}
		segments = append(segments, ASPathSegment{
			Type: segType,
			ASNs: asns,
		})
	}

	return segments, nil
}

func isASPath4(b []byte) (bool, error) {
	if len(b) == 0 {
		return false, fmt.Errorf("invalid AS_PATH attribute: empty buffer")
	}
	// validSegmentType returns true for the four defined AS_PATH segment types:
	//   0x01 AS_SET, 0x02 AS_SEQUENCE, 0x03 AS_CONFED_SEQUENCE, 0x04 AS_CONFED_SET
	validSegmentType := func(t byte) bool {
		return t == 0x01 || t == 0x02 || t == 0x03 || t == 0x04
	}
	// triesWidth walks the full buffer consuming segments of asSize bytes per ASN.
	// Returns true only when all bytes are consumed and every segment type is valid.
	triesWidth := func(asSize int) bool {
		for p := 0; p < len(b); {
			if p+2 > len(b) {
				return false
			}
			if !validSegmentType(b[p]) {
				return false
			}
			l := int(b[p+1])
			p += 2
			if p+l*asSize > len(b) {
				return false
			}
			p += l * asSize
		}
		return true
	}
	switch {
	case triesWidth(4):
		return true, nil
	case triesWidth(2):
		return false, nil
	default:
		return false, fmt.Errorf("invalid AS_PATH attribute: buffer does not parse as either AS2 or AS4 segments")
	}
}

// unmarshalAttrNextHop returns the value of Next Hop attribute
func unmarshalAttrNextHop(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) == 4 {
		return net.IP(b).String()
	}
	if ip := net.IP(b).To16(); ip != nil {
		return ip.String()
	}
	return ""
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

// unmarshalAttrOTC returns the value of the Only to Customer (OTC) attribute (RFC 9234).
// The attribute carries a 4-byte AS number.
func unmarshalAttrOTC(b []byte) uint32 {
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
	comm := make([]uint32, 0, len(b)/4)
	if len(b)%4 != 0 {
		return comm
	}
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
		return net.IP(b).String()
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
		parts[i/4] = net.IP(b[i : i+4]).String()
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
	path := make([]uint32, 0, len(b)/4)
	for p := 0; p < len(b); {
		if p+2 > len(b) {
			glog.Errorf("AS4_PATH truncated at segment header: offset %d, len %d", p, len(b))
			break
		}
		// Segment type byte
		p++
		// Length of path segment in number of 4-byte ASes
		l := int(b[p])
		p++
		if p+l*4 > len(b) {
			glog.Errorf("AS4_PATH truncated: segment needs %d bytes, have %d", l*4, len(b)-p)
			break
		}
		for n := 0; n < l; n++ {
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
