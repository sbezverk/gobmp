package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// CommonHeader defines BMP message Common Header per rfc7854
type CommonHeader struct {
	Version       byte
	MessageLength uint32
	MessageType   byte
}

// IntMessageLength returns the MessageLength as an int with overflow checking.
// It is intended for use in allocations and slicing operations that require an int length.
func (c *CommonHeader) IntMessageLength() (int, error) {
	// Compute platform-specific max int (e.g., 2^31-1 on 32-bit, 2^63-1 on 64-bit).
	maxInt := int(^uint(0) >> 1)
	if c.MessageLength > uint32(maxInt) {
		return 0, fmt.Errorf("bmp: message length %d overflows int (max %d)", c.MessageLength, maxInt)
	}
	return int(c.MessageLength), nil
}
// UnmarshalCommonHeader processes Common Header and returns BMPCommonHeader object
func UnmarshalCommonHeader(b []byte) (*CommonHeader, error) {
	if glog.V(6) {
		glog.Infof("BMP CommonHeader Raw: %s", tools.MessageHex(b))
	}
	if len(b) < CommonHeaderLength {
		return nil, fmt.Errorf("not enough bytes to decode BMP common header, need %d bytes, have %d", CommonHeaderLength, len(b))
	}
	ch := &CommonHeader{}
	if b[0] != 3 {
		return nil, fmt.Errorf("invalid version in common header, expected 3 found %d", b[0])
	}
	ch.Version = b[0]
	ch.MessageLength = binary.BigEndian.Uint32(b[1:5])
	ch.MessageType = b[5]
	// *  Type = 0: Route Monitoring
	// *  Type = 1: Statistics Report
	// *  Type = 2: Peer Down Notification
	// *  Type = 3: Peer Up Notification
	// *  Type = 4: Initiation Message
	// *  Type = 5: Termination Message
	// *  Type = 6: Route Mirroring Message

	// As per RFC 7854 recommendation, BMP implementations MUST ignore messages
	// with unrecognized types and continue processing subsequent messages.
	// Therefore, we will not return an error for unrecognized message types, but we will log a warning.
	if ch.MessageType > 6 {
		glog.Warningf("unknown BMP message type found %d", ch.MessageType)
	}

	return ch, nil
}

// Serialize generates a slice of bytes from CommonHeader structure
func (c *CommonHeader) Serialize() ([]byte, error) {
	b := make([]byte, CommonHeaderLength)
	b[0] = c.Version
	binary.BigEndian.PutUint32(b[1:], uint32(c.MessageLength))
	b[5] = c.MessageType
	return b, nil
}
