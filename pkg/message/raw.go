package message

import (
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// produceRawMessage produces RAW BMP messages in OpenBMP format
// Format per OpenBMP message bus API:
// V: 1.7
// C_HASH_ID: <collector_hash>
// R_HASH: <router_hash>
// R_IP: <router_ip>
// L: <length>
//
// <raw_bmp_message>
func (p *producer) produceRawMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("peer header is nil, cannot produce RAW message")
		return
	}

	rm, ok := msg.Payload.(*bmp.RawMessage)
	if !ok {
		glog.Errorf("invalid payload type for RAW message: %T", msg.Payload)
		return
	}

	// Build OpenBMP header using strings.Builder for performance
	var builder strings.Builder
	builder.Grow(256) // Pre-allocate ~256 bytes for header

	builder.WriteString("V: 1.7\nC_HASH_ID: ")
	builder.WriteString(p.adminHash)
	builder.WriteString("\nR_HASH: ")
	builder.WriteString(msg.PeerHeader.GetPeerHash())
	builder.WriteString("\nR_IP: ")
	builder.WriteString(msg.PeerHeader.GetPeerAddrString())
	builder.WriteString("\nL: ")
	builder.WriteString(strconv.Itoa(len(rm.Msg)))
	builder.WriteString("\n\n")

	// Combine header and raw message
	header := []byte(builder.String())
	out := make([]byte, len(header)+len(rm.Msg))
	copy(out, header)
	copy(out[len(header):], rm.Msg)

	// Publish to raw topic
	if err := p.publisher.PublishMessage(bmp.BMPRawMsg, nil, out); err != nil {
		glog.Errorf("failed to publish RAW message: %v", err)
	}
}
