package unicast

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, pathID)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes
// Improvements added,
// Improved IPv4/IPv6 detection and handling e.g, been parsing msg to kafka topic as 30.223.0.0/64 --> v4
// IPv4 byte order normalization for malformed addresses
// Prefix length calculation and validation
// Enhanced error reporting w position information
// Empty NLRI proper handling
// Detailed debug logging for parsed prefixes
// Aggressive byte order fixing for IPv4 prefixes with wrong lengths
func UnmarshalLUNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Label Unicast NLRI Raw: %s path id flag: %t", tools.MessageHex(b), pathID)
	}

	// Return empty NLRI if no data
	if len(b) == 0 {
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}

	mpnlri := base.MPNLRI{
		NLRI: make([]base.Route, 0),
	}
	var err error = nil
	for p := 0; p < len(b); {
		up := base.Route{
			Label: make([]*base.Label, 0),
		}
		if pathID {
			if p+4 > len(b) {
				err = fmt.Errorf("not enough bytes to reconstruct labeled unicast prefix")
				if glog.V(6) {
					glog.Infof("Error detail: not enough bytes for PathID at position %d (raw data: %s)",
						p, tools.MessageHex(b))
				}
				goto error_handle
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		if p+1 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct labeled unicast prefix")
			if glog.V(6) {
				glog.Infof("Error detail: not enough bytes for prefix length at position %d", p)
			}
			goto error_handle
		}
		up.Length = b[p]
		if up.Length <= 0 {
			err = fmt.Errorf("not enough bytes to reconstruct l3vpn nlri")
			if glog.V(6) {
				glog.Infof("Error detail: invalid prefix length (0 bits) at position %d", p)
			}
			goto error_handle
		}
		p++

		compatibilityField := 0
		if p+3 > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct labeled unicast prefix")
			if glog.V(6) {
				glog.Infof("Error detail: not enough bytes for label field at position %d", p)
			}
			goto error_handle
		}

		// checking for compatibility field (special 3-byte value)
		if bytes.Equal([]byte{0x80, 0x00, 0x00}, b[p:p+3]) {
			up.Label = nil
			compatibilityField = 3
			p += 3
		} else {
			// else parse labels
			up.Label = make([]*base.Label, 0)
			bos := false
			for !bos && p < len(b) {
				if p+3 > len(b) {
					err = fmt.Errorf("not enough bytes to reconstruct label")
					if glog.V(6) {
						glog.Infof("Error detail: not enough bytes for label at position %d", p)
					}
					goto error_handle
				}
				l, e := base.MakeLabel(b[p : p+3])
				if e != nil {
					err = e
					goto error_handle
				}
				up.Label = append(up.Label, l)
				p += 3
				bos = l.BoS
			}
		}

		// Calculate remaining bits for the prefix after labels and compatibility field
		originalLength := up.Length
		labelBits := (len(up.Label) * 3 * 8)
		if up.Label == nil {
			labelBits = compatibilityField * 8
		}

		// Calculate actual prefix length in bits
		prefixBitLen := int(originalLength) - labelBits

		// Validate prefix length for IPv4/IPv6
		if prefixBitLen < 0 {
			// Invalid - use a reasonable default
			if glog.V(6) {
				glog.Warningf("Invalid negative prefix length: %d, using 32 bits", prefixBitLen)
			}
			prefixBitLen = 32
		} else if prefixBitLen > 128 {
			// IPv6 prefixes can't be longer than 128 bits
			if glog.V(6) {
				glog.Warningf("Invalid prefix length: %d bits (too large), capping at 128", prefixBitLen)
			}
			prefixBitLen = 128
		}

		// Additional check for potentially inverted IPv4 addresses with wrong lengths
		// This catches cases like 30.223.0.0/64 which should be 223.0.0.30/32
		if prefixBitLen > 32 && prefixBitLen <= 128 {
			// Check if this could be an IPv4 with wrong length and byte order
			if (int(originalLength) - labelBits) <= 128 {
				// This looks like an IPv4-like address with excessive prefix length
				if glog.V(6) {
					glog.Warningf("Potential IPv4 with wrong prefix length: %d bits; will try to normalize", prefixBitLen)
				}
			}
		}

		// Calculate bytes needed for prefix
		prefixBytes := (prefixBitLen + 7) / 8

		if p+prefixBytes > len(b) {
			err = fmt.Errorf("not enough bytes to reconstruct labeled unicast prefix")
			if glog.V(6) {
				glog.Infof("Error detail: not enough bytes for prefix at position %d (need %d more bytes)",
					p, p+prefixBytes-len(b))
			}
			goto error_handle
		}

		// Copy the prefix bytes
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])

		// Aggressive byte order fixing for IPv4 addresses:
		// 1. If it's already identified as IPv4 (prefixBitLen <= 32)
		// 2. If it has excessive length but could be IPv4 (prefixBytes <= 4)
		if prefixBytes <= 4 {
			// 1. First, always cap excessive IPv4 prefix lengths
			if prefixBitLen > 32 {
				if glog.V(6) {
					glog.Warningf("IPv4-like address with excessive prefix length: %d bits; capping at 32", prefixBitLen)
				}
				prefixBitLen = 32
			}

			// 2. Look for signs of byte order corruption
			needsFix := false

			// Clear signs of corruption:
			// - First octet is 0 (not valid for routable prefixes)
			// - Very high first octet (> 240) that's not a valid IPv4 unicast/multicast
			if prefixBytes > 0 && (up.Prefix[0] == 0 || up.Prefix[0] > 240) {
				needsFix = true
			}

			// 3. Apply fix only when needed
			if needsFix {
				ip := net.IP(append(up.Prefix, make([]byte, 4-len(up.Prefix))...)).To4()
				if ip != nil {
					if glog.V(6) {
						glog.Infof("Fixing IPv4 byte order: %v -> %v",
							net.IP(append(up.Prefix, make([]byte, 4-len(up.Prefix))...)), ip)
					}
					// Copy the corrected bytes back
					copy(up.Prefix, ip[:len(up.Prefix)])
				}
			}
		}

		p += prefixBytes

		// Store the corrected prefix length
		up.Length = uint8(prefixBitLen)

		// Determine if IPv4 based on corrected length
		isIPv4 := prefixBitLen <= 32

		// Logging
		if glog.V(6) {
			// For IPv4
			if isIPv4 {
				padPrefix := make([]byte, 4)
				copy(padPrefix, up.Prefix)
				glog.Infof("Parsed IPv4 labeled unicast: %s/%d (labels: %v)",
					net.IP(padPrefix).String(), prefixBitLen, up.Label)
			} else {
				// For IPv6
				padPrefix := make([]byte, 16)
				copy(padPrefix, up.Prefix)
				glog.Infof("Parsed IPv6 labeled unicast: %s/%d (labels: %v)",
					net.IP(padPrefix).String(), prefixBitLen, up.Label)
			}
		}

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

error_handle:
	// In some cases, Error could be triggered by use of incorrect value of PathID flag
	// BGP Update might not have PathID set due to some conditions (e.g., different AS)
	// Here we attempt to Unmarshal again with reversed value of PathID flag
	if err != nil {
		if pathID {
			// Try again with different pathID flag
			if u, e := UnmarshalLUNLRI(b, !pathID); e == nil {
				return u, nil
			}
		}
		glog.Errorf("failed to reconstruct labeled unicast prefix from slice %s with error: %+v",
			tools.MessageHex(b), err)
		return nil, err
	}

	return &mpnlri, nil
}
