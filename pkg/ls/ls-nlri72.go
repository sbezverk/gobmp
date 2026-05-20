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

// VPNElement defines a single BGP-LS-VPN NLRI entry (RFC 9552 §5.2 Figure 6).
// Each entry is the standard Link-State NLRI Element preceded by an 8-byte
// Route Distinguisher that scopes the link/node/prefix to a VPN.
type VPNElement struct {
	RD     *base.RD
	Type   uint16
	Length uint16 // not including Type and itself
	LS     interface{}
	PathID uint32 // Add Path Path-ID (RFC 7911 §3); zero unless Add Path parsing is enabled
}

// NLRI72 defines Link State NLRI object for SAFI 72 (BGP-LS-VPN) per
// RFC 9552 §5.2. The wire format is identical to SAFI 71 except each Element
// is preceded by an 8-byte Route Distinguisher.
type NLRI72 struct {
	NLRI []VPNElement
}

// UnmarshalLSNLRI72 builds a Link State NLRI object for SAFI 72 per
// RFC 9552 §5.2. When pathID is true the leading 4 bytes of each NLRI entry
// are consumed as the Add Path Path-ID (RFC 7911 §3); the next 8 bytes are
// the Route Distinguisher; the remaining bytes are the standard Link-State
// NLRI (Type+Length+Value) decoded identically to SAFI 71.
func UnmarshalLSNLRI72(b []byte, pathID bool) (*NLRI72, error) {
	if glog.V(6) {
		glog.Infof("LSNLRI72 Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	ls := NLRI72{
		NLRI: make([]VPNElement, 0),
	}
	for p := 0; p < len(b); {
		el := VPNElement{}
		if pathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("NLRI72 truncated: need 4 bytes for Add Path Path-ID at offset %d, have %d", p, len(b)-p)
			}
			el.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		if p+8 > len(b) {
			return nil, fmt.Errorf("NLRI72 truncated at offset %d: need 8 bytes for Route Distinguisher, have %d", p, len(b)-p)
		}
		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return nil, fmt.Errorf("NLRI72 invalid Route Distinguisher at offset %d: %w", p, err)
		}
		el.RD = rd
		p += 8
		if p+4 > len(b) {
			return nil, fmt.Errorf("NLRI72 truncated at offset %d: need 4 bytes for TLV header, have %d", p, len(b)-p)
		}
		el.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		el.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if el.Length == 0 {
			return nil, fmt.Errorf("NLRI72 TLV type %d has invalid zero length at offset %d", el.Type, p-4)
		}
		if p+int(el.Length) > len(b) {
			return nil, fmt.Errorf("NLRI72 TLV type %d truncated at offset %d: need %d bytes, have %d", el.Type, p, el.Length, len(b)-p)
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
