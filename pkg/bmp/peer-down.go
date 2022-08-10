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
	pdw := &PeerDownMessage{
		Data: make([]byte, len(b)-1),
	}
	p := 0
	pdw.Reason = b[p]
	p++
	if pdw.Reason < 1 || pdw.Reason > 5 {
		return nil, fmt.Errorf("invalid reason code %d in Peer Down message", pdw.Reason)
	}
	copy(pdw.Data, b[p:])

	return pdw, nil
}
