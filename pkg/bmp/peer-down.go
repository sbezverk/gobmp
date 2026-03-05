package bmp

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// PeerDownMessage defines BMPPeerDownMessage per rfc7854
type PeerDownMessage struct {
	Reason uint8
	Data   []byte
}

// UnmarshalPeerDownMessage processes Peer Down message and returns BMPPeerDownMessage object
func UnmarshalPeerDownMessage(b []byte) (*PeerDownMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Peer Down Message Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to decode BMP Peer Down message, Reason field, need at least 1 byte, have %d", len(b))
	}
	pdw := &PeerDownMessage{
		Data: make([]byte, len(b)-1),
	}
	p := 0
	pdw.Reason = b[p]
	// Reason 0 is explicitly Reserved by RFC 7854 §10.8 and MUST NOT be sent;
	// reject it as it indicates a broken sender.
	// Reason 6 was added by RFC 9069 §5.3 for Loc-RIB Peer Down.
	// All other unknown reason codes should be accepted to remain forward-compatible
	// with future IANA assignments.
	if pdw.Reason == 0 {
		return nil, fmt.Errorf("reserved reason code 0 in Peer Down message")
	}
	p++
	switch pdw.Reason {
	// valid reason codes defined in RFC 7854 and RFC 9069
	case 1, 2, 3, 4, 5, 6:
		copy(pdw.Data, b[p:])
	default:
		// As per RFC 7854 recommendation, BMP implementations MUST ignore messages
		// with unrecognized reason codes and continue processing subsequent messages.
		// Therefore, we will not return an error for unrecognized reason codes, but we will log a warning.
		glog.Warningf("unknown reason code %d in Peer Down message", pdw.Reason)
	}

	return pdw, nil
}
