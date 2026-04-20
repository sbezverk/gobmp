package ls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/te"
	"github.com/sbezverk/tools"
)

// Element defines a generic NLRI object carried in NLRI type 71,
// the type of the object will be used to cast it into a corresponding to a specific type structure.
type Element struct {
	Type   uint16
	Length uint16 // Not including Type and itself
	LS     interface{}
}

// NLRI71 defines Link State NLRI object for SAFI 71
// https://tools.ietf.org/html/rfc7752#section-3.2
type NLRI71 struct {
	Type   uint16
	Length uint16 // Not including Type and itself
	LS     []byte
	NLRI   []Element
}

// UnmarshalLSNLRI71 builds Link State NLRI object for SAFI 71
func UnmarshalLSNLRI71(b []byte) (*NLRI71, error) {
	if glog.V(6) {
		glog.Infof("LSNLRI71 Raw: %s ", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	// Some router implementations (e.g. IOS-XR) prepend a 4-byte vendor-specific
	// prefix before the standard RFC 7752 NLRI TLVs. Type 0 is unassigned and not
	// a valid BGP-LS NLRI type, so when it appears at the start and the bytes at
	// offset 4 carry a known NLRI type (1–6), treat the first 4 bytes as an opaque
	// vendor prefix and skip them.
	if len(b) >= 6 && binary.BigEndian.Uint16(b[0:2]) == 0 {
		if t := binary.BigEndian.Uint16(b[4:6]); t >= 1 && t <= 6 {
			if glog.V(5) {
				glog.Infof("NLRI71: skipping 4-byte vendor prefix %s", tools.MessageHex(b[0:4]))
			}
			b = b[4:]
		}
	}
	ls := NLRI71{
		NLRI: make([]Element, 0),
	}
	for p := 0; p < len(b); {
		if p+4 > len(b) {
			return nil, fmt.Errorf("NLRI71 truncated at offset %d: need 4 bytes for TLV header, have %d", p, len(b)-p)
		}
		el := Element{}
		el.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		el.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if el.Length == 0 {
			return nil, fmt.Errorf("NLRI71 TLV type %d has invalid zero length at offset %d", el.Type, p-4)
		}
		if p+int(el.Length) > len(b) {
			return nil, fmt.Errorf("NLRI71 TLV type %d truncated at offset %d: need %d bytes, have %d", el.Type, p, el.Length, len(b)-p)
		}

		switch el.Type {
		case 1:
			n, err := base.UnmarshalNodeNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 2:
			n, err := base.UnmarshalLinkNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 3:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], true)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 4:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], false)
			if err != nil {
				return nil, err
			}
			el.LS = n
			// TE Policy (SR Policy) NLRI - handled below in case 5
			// Reference: draft-ietf-idr-te-lsp-distribution-14
		case 5:
			n, err := te.UnmarshalTEPolicyNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 6:
			n, err := srv6.UnmarshalSRv6SIDNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		default:
			el.LS = make([]byte, el.Length)
			copy(el.LS.([]byte), b[p:p+int(el.Length)])
		}
		p += int(el.Length)

		ls.NLRI = append(ls.NLRI, el)
	}

	return &ls, nil
}
