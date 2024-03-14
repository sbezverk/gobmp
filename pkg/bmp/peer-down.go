package bmp

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

// PeerDownMessage defines BMPPeerDownMessage per rfc7854
type PeerDownMessage struct {
	Reason       uint8
	Data         []byte
	Notification *bgp.NotificationMessage
	Description  string
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
	switch pdw.Reason {
	case 1:
		fallthrough
	case 3:
		// both reason code 1 & 3 contains BGP Notificaiton message
		copy(pdw.Data, b[p:])
		u, err := bgp.UnmarshalBGPNotificationMessage(b[p:])
		if err != nil {
			return nil, err
		}
		pdw.Notification = u
		pdw.Description = "Remote system closed, " + u.String()
		if pdw.Reason == 1 {
			pdw.Description = "Local system closed, " + u.String()
		}
	case 2:
		pdw.Description = "The local system closed the session, FSM error"
	case 4:
		pdw.Description = "Remote system closed, no data"
	case 5:
		pdw.Description = "Peer de-configured"
	case 6:
		tlvs, err := UnmarshalTLV(b[p:])
		if err != nil {
			return nil, err
		}
		if len(tlvs) > 1 {
			return nil, fmt.Errorf("BMP Peer Down, Reason Code 6 contains more than one TLV")
		}
		if tlvs[0].InformationType != 3 {
			return nil, fmt.Errorf("BMP Peer Down, Reason Code 6 invalid TLV type:%v", tlvs[0].InformationType)
		}
		pdw.Description = "Local system closed, vrf:" + string(tlvs[0].Information)
	default:
		pdw.Description = fmt.Sprintf("Invalid Peer Down Reason Code:%v", pdw.Reason)
	}
	return pdw, nil
}
