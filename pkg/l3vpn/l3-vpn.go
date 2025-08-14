package l3vpn

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalL3VPNNLRI tries to parse the L3VPN NLRI once using the given pathID, and if that fails, it tries again
// once with !pathID. This avoids infinite recursion and prevents stack overflows...
func UnmarshalL3VPNNLRI(b []byte, pathID bool, srv6 ...bool) (*base.MPNLRI, error) {
	if len(b) == 0 {
		// Return empty NLRI structure instead of error
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}
	srv6Flag := false
	if len(srv6) == 1 {
		srv6Flag = srv6[0]
	}
	if glog.V(6) {
		glog.Infof("L3VPN NLRI Raw: %s, pathID: %t, srv6: %t", tools.MessageHex(b), pathID, srv6Flag)
	}

	// Try parsing with the given pathID
	mpnlri, err := parseL3VPNNLRI(b, pathID, srv6Flag)
	if err == nil {
		return mpnlri, nil
	}

	// If fails, try once with !pathID
	mpnlri2, err2 := parseL3VPNNLRI(b, !pathID, srv6Flag)
	if err2 == nil {
		return mpnlri2, nil
	}

	// Both attempts failed; return the first error with raw data
	return nil, fmt.Errorf("%v (raw data: %s)", err, tools.MessageHex(b))
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
				return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for PathID at position %d", p))
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}

		// Next byte: total NLRI length (in bits)
		if p >= len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("no bytes left for NLRI length at position %d", p))
		}
		up.Length = b[p]
		if up.Length == 0 {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("invalid NLRI length (0 bits) at position %d", p))
		}
		p++

		// Next 3 bytes: label or compatibility field
		if p+3 > len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for label field at position %d", p))
		}
		labelField := b[p : p+3]
		if bytes.Equal(labelField, []byte{0x80, 0x00, 0x00}) || bytes.Equal(labelField, []byte{0x00, 0x00, 0x00}) {
			// No labels present
			up.Label = nil
			p += 3
		} else {
			// Parse one or more 3-byte labels
			up.Label = make([]*base.Label, 0)
			var done bool
			for !done {
				if p+3 > len(b) {
					return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for label at position %d (raw data: %s)",
						p, tools.MessageHex(b)))
				}
				l, err := base.MakeLabel(b[p:p+3], srv6Flag)
				if err != nil {
					return mpnlriOrErr(&mpnlri, fmt.Errorf("failed to parse label at position %d: %v", p, err))
				}
				up.Label = append(up.Label, l)
				p += 3

				// Set done flag based on SRv6 or BoS
				done = srv6Flag || l.BoS
			}
		}

		// Next 8 bytes: the Route Distinguisher
		if p+8 > len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for RD at position %d (need 8 bytes)", p))
		}

		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("failed to parse RD at position %d: %v", p, err))
		}
		up.RD = rd
		p += 8

		// Calculate overhead in bits: label field + 64 bits for RD
		labelBytes := 3 // default (compatibility) if no actual label
		if up.Label != nil {
			labelBytes = len(up.Label) * 3
		}
		overheadBits := (labelBytes * 8) + 64

		// Compute prefix bit length
		prefixBitLen := int(up.Length) - overheadBits
		if prefixBitLen <= 0 || prefixBitLen > 128 {
			// If wrong calculation, assume IPv4 length
			if glog.V(6) {
				glog.Warningf("Invalid prefix length calculation: %d bits; forcing to 32 bits", prefixBitLen)
			}
			prefixBitLen = 32
		}

		// Calculate how many bytes we need for the prefix
		prefixBytes := (prefixBitLen + 7) / 8
		if p+prefixBytes > len(b) {
			return mpnlriOrErr(&mpnlri, fmt.Errorf("not enough bytes for prefix at position %d (need %d bytes)", p, prefixBytes))
		}

		// Copy the prefix bytes
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])

		// IP byte order issues for v4 prefixes..
		if prefixBitLen <= 32 && prefixBytes > 0 {
			if prefixBytes >= 4 && up.Prefix[0] == 0 {
				ip := net.IP(up.Prefix[:4]).To4()
				if ip != nil {
					if glog.V(6) {
						glog.Infof("Fixing IPv4 byte order: %v -> %v", up.Prefix[:4], ip)
					}
					copy(up.Prefix[:4], ip)
				}
			} else if prefixBytes < 4 && up.Prefix[0] == 0 {
				// For prefixes shorter than 4 bytes with leading zero
				if glog.V(6) {
					glog.Warningf("Short prefix with leading zero detected: %v", up.Prefix)
				}
			}
		}

		p += prefixBytes

		// Set the actual prefix length (important for netmask)
		up.Length = uint8(prefixBitLen)

		// Log the correctly parsed route for debugging
		if glog.V(6) {
			if prefixBitLen <= 32 {
				ipStr := "invalid"
				if len(up.Prefix) >= 4 {
					ipStr = net.IP(append(up.Prefix[:4], make([]byte, 4-len(up.Prefix))...)).String()
				}
				glog.Infof("Parsed IPv4 VPN route: %s/%d, RD=%s", ipStr, prefixBitLen, up.RD.String())
			} else {
				ipStr := "invalid"
				if len(up.Prefix) <= 16 {
					ipStr = net.IP(append(up.Prefix, make([]byte, 16-len(up.Prefix))...)).String()
				}
				glog.Infof("Parsed IPv6 VPN route: %s/%d, RD=%s", ipStr, prefixBitLen, up.RD.String())
			}
		}

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}

// mpnlriOrErr is a helper that logs detailed information and returns the error
func mpnlriOrErr(m *base.MPNLRI, err error) (*base.MPNLRI, error) {
	// Log partial parsing results if available
	if m != nil && len(m.NLRI) > 0 {
		glog.Warningf("Partial parsing results before error: %d routes parsed", len(m.NLRI))
		for i, route := range m.NLRI {
			prefixStr := "invalid"
			if len(route.Prefix) > 0 {
				if route.Length <= 32 {
					// IPv4
					paddedPrefix := append(route.Prefix, make([]byte, 4-len(route.Prefix))...)
					prefixStr = net.IP(paddedPrefix).String()
				} else {
					// IPv6
					paddedPrefix := append(route.Prefix, make([]byte, 16-len(route.Prefix))...)
					prefixStr = net.IP(paddedPrefix).String()
				}
			}
			glog.V(2).Infof("Route[%d]: %s/%d, RD=%s", i, prefixStr, route.Length, route.RD.String())
		}
	}

	return nil, err
}
