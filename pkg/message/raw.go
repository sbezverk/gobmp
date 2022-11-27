package message

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// produceStatsMessage proceduces message from BMP Statistic Message
func (p *producer) produceRawMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		// XXX
		glog.Errorf("perPeerHeader is missing, cannot construct proper raw message")
		return
	}
	rm, ok := msg.Payload.(*bmp.RawMessage)
	if !ok {
		glog.Errorf("got invalid Payload type in bmp.RawMessage %+v", msg.Payload)
		return
	}

	out := []byte(fmt.Sprintf("V: 1.7\nC_HASH_ID: %s\nR_HASH: %s\nR_IP: %s\nL: %d\n\n",
		p.adminHash, msg.PeerHeader.GetPeerHash(),
		msg.PeerHeader.GetPeerAddrString(), len(rm.Msg)))
	out = append(out, rm.Msg...)

	if err := p.publisher.PublishMessage(bmp.BMPRawMsg, []byte(msg.PeerHeader.GetPeerHash()), out); err != nil {
		glog.Errorf("failed to publish a raw BMP message to kafka with error: %+v", err)
		return
	}
}
