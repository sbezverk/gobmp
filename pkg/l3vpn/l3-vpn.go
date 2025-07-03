package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalL3VPNNLRI tries to parse the L3VPN NLRI once using the given pathID, and if that fails, it tries again
// once with !pathID. This avoids infinite recursion and prevents stack overflows...
func UnmarshalL3VPNNLRI(b []byte, pathID bool, srv6 ...bool) (*base.MPNLRI, error) {
	srv6Flag := false
	if len(srv6) == 1 {
		srv6Flag = srv6[0]
	}
	if glog.V(6) {
		glog.Infof("L3VPN NLRI Raw: %s, pathID: %t, srv6: %t", tools.MessageHex(b), pathID, srv6Flag)
	}

	// 1) Try parsing with the given pathID
	mpnlri, err := parseL3VPNNLRI(b, pathID, srv6Flag)
	if err == nil {
		return mpnlri, nil
	}

	// 2) If fails, try once with !pathID
	mpnlri2, err2 := parseL3VPNNLRI(b, !pathID, srv6Flag)
	if err2 == nil {
		return mpnlri2, nil
	}

	// 3) Both attempts failed; return the first error
	return nil, err
}

// parseL3VPNNLRI do not call itself recursively on error
func parseL3VPNNLRI(b []byte, pathID bool, srv6Flag bool) (*base.MPNLRI, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}

	mpnlri := base.MPNLRI{NLRI: make([]base.Route, 0)}
	p := 0

	for p < len(b) {
		up := base.Route{
			Label: make([]*base.Label, 0),
		}

		// (Optional) 4-byte PathID
		if pathID {
			if p+4 > len(b) {
				// Not enough bytes for a PathID
				return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for PathID"))
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}

		// Next byte: total NLRI length (in bits)
		if p >= len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("no bytes left for NLRI length"))
		}
		up.Length = b[p]
		if up.Length == 0 {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("invalid NLRI length (0 bits)"))
		}
		p++

		// Next 3 bytes: label or compatibility field
		if p+3 > len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for label field"))
		}
		labelField := b[p : p+3]
		if bytes.Equal(labelField, []byte{0x80, 0x00, 0x00}) || bytes.Equal(labelField, []byte{0x00, 0x00, 0x00}) {
			// No labels present
			up.Label = nil
			p += 3
		} else {
			// Parse one or more 3-byte labels
			for {
				if p+3 > len(b) {
					// Not enough bytes to read the next label
					break
				}
				l, err := base.MakeLabel(b[p:p+3], srv6Flag)
				if err != nil {
					// Could not parse label; bail out!
					break
				}
				up.Label = append(up.Label, l)
				p += 3
				if srv6Flag {
					// For SRv6, only one 3-byte chunk
					break
				}
				if l.BoS {
					break
				}
			}
		}

		// Next 8 bytes: the Route Distinguisher
		var rd *base.RD
		if p+8 > len(b) {
			// Not enough bytes for RD; use default
			rd = &base.RD{
				Type:  1,
				Value: []byte{0, 0, 0, 0, 0, 0},
			}
		} else {
			var err error
			rd, err = base.MakeRD(b[p : p+8])
			if err != nil {
				// RD parse failed; use default
				rd = &base.RD{
					Type:  1,
					Value: []byte{0, 0, 0, 0, 0, 0},
				}
			}
			p += 8
		}
		up.RD = rd

		// Calculate overhead in bits: label field + 64 bits for RD
		labelBytes := 3 // default (compatibility) if no actual label
		if up.Label != nil {
			labelBytes = len(up.Label) * 3
		}
		overheadBits := (labelBytes * 8) + 64

		// Compute prefix bit length
		computedPrefixBits := int(up.Length) - overheadBits

		// For IPv4 L3VPN, if bits < 32, force to 32 bits
		if computedPrefixBits < 32 {
			computedPrefixBits = 32
		}

		prefixBytes := (computedPrefixBits + 7) / 8
		if p+prefixBytes > len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for prefix"))
		}
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])
		p += prefixBytes

		// Set the route's prefix length
		up.Length = uint8(computedPrefixBits)

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}

// mpnlriOrErr is a small helper that returns either the partial MPNLRI
// or an error, so we can short-circuit with an error...
// while still returning a result if needed. We always return an error
func mpnlriOrErr(m *base.MPNLRI, err error) (*base.MPNLRI, error) {
	return m, err
}
