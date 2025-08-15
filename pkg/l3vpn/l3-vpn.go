package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalL3VPNNLRI parses VPNv4/VPNv6 NLRI according to the caller-provided pathID flag
// If parsing fails, it will try exactly once with !pathID. No recursion...
func UnmarshalL3VPNNLRI(b []byte, pathID bool, srv6 ...bool) (*base.MPNLRI, error) {
	srv6Flag := false
	if len(srv6) == 1 {
		srv6Flag = srv6[0]
	}
	if glog.V(6) {
		glog.Infof("L3VPN NLRI Raw: %s, pathID: %t, srv6: %t", tools.MessageHex(b), pathID, srv6Flag)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}

	// First attempt with the provided pathID flag
	if mp, err := parseL3VPNNLRI(b, pathID, srv6Flag); err == nil {
		return mp, nil
	}

	// Single fallback attempt with flipped pathID
	if mp, err := parseL3VPNNLRI(b, !pathID, srv6Flag); err == nil {
		return mp, nil
	} else {
		return nil, err
	}
}

// parseL3VPNNLRI performs the actual parsing without any recursion
func parseL3VPNNLRI(b []byte, pathID bool, srv6Flag bool) (*base.MPNLRI, error) {
	mpnlri := base.MPNLRI{NLRI: make([]base.Route, 0)}
	p := 0

	for p < len(b) {
		up := base.Route{Label: make([]*base.Label, 0)}

		// Optional Path ID (4 bytes)
		if pathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes for PathID at pos %d", p)
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}

		// NLRI length in bits (covers label or compat field + RD + prefix)
		if p >= len(b) {
			return nil, fmt.Errorf("missing NLRI length at pos %d", p)
		}
		up.Length = b[p]
		if up.Length == 0 {
			return nil, fmt.Errorf("invalid NLRI length (0 bits) at pos %d", p)
		}
		p++

		// Label or compatibility (3 bytes)
		// Treat both 0x80 00 00 and 0x00 00 00 as 'no label' markers (common in withdrawals)
		if p+3 > len(b) {
			return nil, fmt.Errorf("not enough bytes for label/compat field at pos %d", p)
		}
		labelField := b[p : p+3]
		if bytes.Equal(labelField, []byte{0x80, 0x00, 0x00}) ||
			bytes.Equal(labelField, []byte{0x00, 0x00, 0x00}) {
			up.Label = nil
			p += 3
		} else {
			// Parse one or more 3-byte labels until BoS (or once if SRv6)
			for {
				if p+3 > len(b) {
					return nil, fmt.Errorf("not enough bytes for label at pos %d", p)
				}
				l, err := base.MakeLabel(b[p:p+3], srv6Flag)
				if err != nil {
					return nil, fmt.Errorf("failed to parse label at pos %d: %v", p, err)
				}
				up.Label = append(up.Label, l)
				p += 3
				if srv6Flag || l.BoS {
					break
				}
			}
		}

		// Route Distinguisher (8 bytes)
		if p+8 > len(b) {
			return nil, fmt.Errorf("not enough bytes for RD at pos %d", p)
		}
		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return nil, fmt.Errorf("failed to parse RD at pos %d: %v", p, err)
		}
		up.RD = rd
		p += 8

		// Overhead in bits: (label bytes or 3 bytes for compat) + 8-byte RD
		labelBytes := 3
		if up.Label != nil {
			labelBytes = len(up.Label) * 3
		}
		overheadBits := (labelBytes * 8) + 64

		// Exact prefix length in bits
		prefixBits := int(up.Length) - overheadBits
		if prefixBits < 0 || prefixBits > 128 {
			return nil, fmt.Errorf("invalid computed prefix length %d bits (NLRI=%d, overhead=%d)",
				prefixBits, up.Length, overheadBits)
		}

		// Bytes to read for the prefix (ceil to octet)
		prefixBytes := (prefixBits + 7) / 8
		if p+prefixBytes > len(b) {
			return nil, fmt.Errorf("not enough bytes for prefix at pos %d (need %d)", p, prefixBytes)
		}
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])
		p += prefixBytes

		// Store bit length
		finalBits := prefixBits
		if finalBits > 0 && finalBits <= 32 && (finalBits%8 != 0) {
			finalBits = ((finalBits + 7) / 8) * 8 // round up to 8-bit boundary
		}
		up.Length = uint8(finalBits)

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
