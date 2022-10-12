package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	BMP_HEADER_SIZE = 6
)

// CommonHeader defines BMP message Common Header per rfc7854
type CommonHeader struct {
	Version       byte
	MessageLength int32
	MessageType   byte
}

// UnmarshalCommonHeader processes Common Header and returns BMPCommonHeader object
func UnmarshalCommonHeader(b []byte) (*CommonHeader, error) {
	if glog.V(6) {
		glog.Infof("BMP CommonHeader Raw: %s", tools.MessageHex(b))
	}
	ch := &CommonHeader{}
	if b[0] != 3 {
		return nil, fmt.Errorf("invalid version in common header, expected 3 found %d", b[0])
	}
	ch.Version = b[0]
	ch.MessageLength = int32(binary.BigEndian.Uint32(b[1:5]))
	ch.MessageType = b[5]
	// *  Type = 0: Route Monitoring
	// *  Type = 1: Statistics Report
	// *  Type = 2: Peer Down Notification
	// *  Type = 3: Peer Up Notification
	// *  Type = 4: Initiation Message
	// *  Type = 5: Termination Message
	// *  Type = 6: Route Mirroring Message
	switch ch.MessageType {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	default:
		return nil, fmt.Errorf("invalid message type in common header, expected between 0 and 6 found %d", b[5])
	}

	return ch, nil
}

// Serialize generates a slice of bytes from CommonHeader structure
func (c *CommonHeader) Serialize() ([]byte, error) {
	b := make([]byte, BMP_HEADER_SIZE)
	b[0] = c.Version
	binary.BigEndian.PutUint32(b[1:], uint32(c.MessageLength))
	b[5] = c.MessageType
	return b, nil
}
