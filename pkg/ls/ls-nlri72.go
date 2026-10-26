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
// Its value starts with an 8-byte Route Distinguisher that scopes the
// link/node/prefix to a VPN, followed by the Link-State NLRI body.
type VPNElement struct {
	RD     *base.RD
	Type   uint16
	Length uint16 // includes the RD, but not Type or Length itself
	LS     interface{}
	PathID uint32 // Add Path Path-ID (RFC 7911 §3); zero unless Add Path parsing is enabled
}

// NLRI72 defines Link State NLRI object for SAFI 72 (BGP-LS-VPN) per
// RFC 9552 §5.2. Each element has a Type/Length header followed by an 8-byte
// Route Distinguisher and the Link-State NLRI body.
type NLRI72 struct {
	NLRI []VPNElement
}

// UnmarshalLSNLRI72 builds a Link State NLRI object for SAFI 72 per
// RFC 9552 §5.2. When pathID is true the leading 4 bytes of each NLRI entry
// are consumed as the Add Path Path-ID (RFC 7911 §3). The Type/Length header
// precedes the Route Distinguisher and Link-State body, and Length includes
// the Route Distinguisher (RFC 9552 §5.2 Figure 6).
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
		if p+4 > len(b) {
			return nil, fmt.Errorf("NLRI72 truncated at offset %d: need 4 bytes for TLV header, have %d", p, len(b)-p)
		}
		el.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		el.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if el.Length < 8 {
			return nil, fmt.Errorf("NLRI72 TLV type %d has invalid value length at offset %d: need 8 bytes for Route Distinguisher, have %d", el.Type, p-4, el.Length)
		}
		if p+int(el.Length) > len(b) {
			return nil, fmt.Errorf("NLRI72 TLV type %d truncated at offset %d: need %d bytes, have %d", el.Type, p, el.Length, len(b)-p)
		}
		end := p + int(el.Length)
		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return nil, fmt.Errorf("NLRI72 invalid Route Distinguisher at offset %d: %w", p, err)
		}
		el.RD = rd
		p += 8
		body := b[p:end]

		switch el.Type {
		case 1:
			n, err := base.UnmarshalNodeNLRI(body)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 2:
			n, err := base.UnmarshalLinkNLRI(body)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 3:
			n, err := base.UnmarshalPrefixNLRI(body, true)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 4:
			n, err := base.UnmarshalPrefixNLRI(body, false)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 5:
			n, err := te.UnmarshalTEPolicyNLRI(body)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 6:
			n, err := srv6.UnmarshalSRv6SIDNLRI(body)
			if err != nil {
				return nil, err
			}
			el.LS = n
		default:
			el.LS = make([]byte, len(body))
			copy(el.LS.([]byte), body)
		}
		p = end

		ls.NLRI = append(ls.NLRI, el)
	}

	return &ls, nil
}
