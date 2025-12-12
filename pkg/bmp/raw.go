package bmp

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// RawMessage defines BMP RAW message structure for unprocessed BMP messages
// Used for OpenBMP message bus API compatibility
type RawMessage struct {
	Msg []byte
}

// UnmarshalBMPRawMessage builds BMP RAW message object from raw bytes
// No parsing is performed - the entire BMP message is stored as-is
func UnmarshalBMPRawMessage(b []byte) (*RawMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP RAW Message Raw: %s", tools.MessageHex(b))
	}
	if len(b) < CommonHeaderLength {
		return nil, fmt.Errorf("invalid BMP message length: %d bytes, expected at least %d", len(b), CommonHeaderLength)
	}
	rm := &RawMessage{
		Msg: make([]byte, len(b)),
	}
	copy(rm.Msg, b)

	return rm, nil
}
