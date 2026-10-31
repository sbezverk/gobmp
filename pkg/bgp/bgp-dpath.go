package bgp

import (
	"encoding/binary"
	"fmt"
)

const (
	dPathDomainSize     = 7
	dPathMinSegmentSize = 1 + dPathDomainSize
)

// DPath represents the ordered domain segments of the BGP D-PATH attribute.
// Per RFC 10039 Section 4, D-PATH is optional and transitive (attribute 36).
type DPath struct {
	Segments []DPathSegment `json:"segments"`
}

// DPathSegment contains an ordered sequence of domains (RFC 10039 Section 4).
type DPathSegment struct {
	Domains []DPathDomain `json:"domains"`
}

// DPathDomain identifies a traversed domain and its ISF SAFI (RFC 10039 Section 4).
// GlobalAdmin is an arbitrary administrator value, not necessarily an IP address.
type DPathDomain struct {
	GlobalAdmin uint32 `json:"global_admin"`
	LocalAdmin  uint16 `json:"local_admin"`
	ISFSAFIType uint8  `json:"isf_safi_type"`
}

// UnmarshalDPath decodes the value of a BGP D-PATH attribute.
// Per RFC 10039 Section 4, each segment has a one-octet domain count followed
// by seven octets per domain. Unknown ISF_SAFI_TYPE values are preserved.
func UnmarshalDPath(b []byte) (*DPath, error) {
	if len(b) < dPathMinSegmentSize {
		return nil, fmt.Errorf("d-path attribute: need at least %d bytes, got %d", dPathMinSegmentSize, len(b))
	}
	dpath := &DPath{}
	for p := 0; p < len(b); {
		if len(b)-p < dPathMinSegmentSize {
			return nil, fmt.Errorf("d-path segment at offset %d: need at least %d bytes, got %d", p, dPathMinSegmentSize, len(b)-p)
		}
		count := int(b[p])
		if count == 0 {
			return nil, fmt.Errorf("d-path segment at offset %d: domain count is zero", p)
		}
		segmentSize := 1 + count*dPathDomainSize
		if segmentSize > len(b)-p {
			return nil, fmt.Errorf("d-path segment at offset %d: need %d bytes, got %d", p, segmentSize, len(b)-p)
		}
		p++
		segment := DPathSegment{Domains: make([]DPathDomain, count)}
		for i := range segment.Domains {
			segment.Domains[i] = DPathDomain{
				GlobalAdmin: binary.BigEndian.Uint32(b[p : p+4]),
				LocalAdmin:  binary.BigEndian.Uint16(b[p+4 : p+6]),
				ISFSAFIType: b[p+6],
			}
			p += dPathDomainSize
		}
		dpath.Segments = append(dpath.Segments, segment)
	}
	return dpath, nil
}
