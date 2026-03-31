package bgp

import (
	"encoding/binary"
	"fmt"
)

// AttrSet defines the ATTR_SET attribute structure per RFC 6368.
//
// The attribute carries an Origin AS (the AS that created the set) followed by
// a variable-length sequence of BGP path attributes encoded in the same TLV
// format used in UPDATE messages. Recursive ATTR_SET is explicitly forbidden
// by the RFC and rejected by the parser.
type AttrSet struct {
	OriginAS       uint32          `json:"origin_as"`
	PathAttributes *BaseAttributes `json:"path_attributes,omitempty"`
}

// UnmarshalAttrSet parses an ATTR_SET attribute value (RFC 6368 §2).
//
// Wire format (after the common path-attribute header):
//
//	+-----------------------------------------+
//	| Origin AS (4 octets)                    |
//	+-----------------------------------------+
//	| Path Attributes (variable)              |
//	+-----------------------------------------+
//
// The embedded path attributes are first decoded into raw TLVs via
// unmarshalRawPathAttributes (no semantic mapping), then checked for forbidden
// types, and only then passed to unmarshalBaseAttrsFromSlice. This avoids
// unbounded recursion: a nested ATTR_SET (type 128) is rejected before
// semantic mapping would trigger another call to UnmarshalAttrSet.
func UnmarshalAttrSet(b []byte) (*AttrSet, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("ATTR_SET too short: need 4 bytes for Origin AS, have %d", len(b))
	}

	originAS := binary.BigEndian.Uint32(b[:4])
	attrSet := &AttrSet{
		OriginAS: originAS,
	}

	// No embedded attributes is valid (Origin AS only).
	if len(b) == 4 {
		return attrSet, nil
	}

	// Parse the embedded bytes into raw TLVs only — no semantic mapping yet,
	// so case 128 in unmarshalBaseAttrsFromSlice is never reached.
	attrs, err := unmarshalRawPathAttributes(b[4:])
	if err != nil {
		return nil, fmt.Errorf("ATTR_SET: failed to parse embedded path attributes: %w", err)
	}

	// RFC 6368 §2: ATTR_SET MUST NOT contain MP_REACH_NLRI (14),
	// MP_UNREACH_NLRI (15), or another ATTR_SET (128).
	for _, a := range attrs {
		switch a.AttributeType {
		case 14:
			return nil, fmt.Errorf("ATTR_SET must not contain MP_REACH_NLRI (type 14)")
		case 15:
			return nil, fmt.Errorf("ATTR_SET must not contain MP_UNREACH_NLRI (type 15)")
		case 128:
			return nil, fmt.Errorf("ATTR_SET must not contain a nested ATTR_SET (type 128)")
		}
	}

	baseAttrs, err := unmarshalBaseAttrsFromSlice(attrs)
	if err != nil {
		return nil, fmt.Errorf("ATTR_SET: failed to build BaseAttributes from embedded attributes: %w", err)
	}
	attrSet.PathAttributes = baseAttrs

	return attrSet, nil
}
