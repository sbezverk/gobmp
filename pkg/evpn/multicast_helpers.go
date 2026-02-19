package evpn

import "fmt"

// parseVariableLengthAddr parses a variable-length address field from wire format
// Returns: address bytes, new position, error
// Used for multicast source/group addresses and originator addresses in Type 6/7/10 routes
func parseVariableLengthAddr(b []byte, p int, lengthBits uint8, fieldName string, allowZero bool) ([]byte, int, error) {
	// Validate length value
	var addrBytes int
	switch lengthBits {
	case 0:
		if !allowZero {
			return nil, p, fmt.Errorf("invalid %s length: %d (must be 32 or 128)", fieldName, lengthBits)
		}
		addrBytes = 0
	case 32:
		addrBytes = 4
	case 128:
		addrBytes = 16
	default:
		if allowZero {
			return nil, p, fmt.Errorf("invalid %s length: %d (must be 0, 32, or 128)", fieldName, lengthBits)
		}
		return nil, p, fmt.Errorf("invalid %s length: %d (must be 32 or 128)", fieldName, lengthBits)
	}

	// Check if enough bytes available
	if p+addrBytes > len(b) {
		return nil, p, fmt.Errorf("truncated %s: need %d bytes, have %d", fieldName, addrBytes, len(b)-p)
	}

	// Parse address bytes (if any)
	if addrBytes == 0 {
		return nil, p, nil
	}

	addr := make([]byte, addrBytes)
	copy(addr, b[p:p+addrBytes])
	return addr, p + addrBytes, nil
}
