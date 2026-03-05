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
