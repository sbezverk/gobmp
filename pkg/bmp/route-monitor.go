package bmp

import (
	"errors"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

// ErrNotAnUpdate is returned when a BMP Route Monitor message contains a
// non-Update BGP message type. Callers should skip the message and continue
// processing the stream rather than terminating the connection.
var ErrNotAnUpdate = errors.New("route monitor: BGP message is not an UPDATE")

// RouteMonitor defines a structure of BMP Route Monitoring message
type RouteMonitor struct {
	Update *bgp.Update
}

// UnmarshalBMPRouteMonitorMessage builds a BMP Route Monitor object. AS_PATH
// width in the embedded BGP Update is inferred by heuristic; use
// UnmarshalBMPRouteMonitorMessageWithAS4Hint when the caller has an
// authoritative indicator (typically from the BMP Per-Peer Header).
func UnmarshalBMPRouteMonitorMessage(b []byte) (*RouteMonitor, error) {
	return unmarshalBMPRouteMonitorMessage(b, nil)
}

// UnmarshalBMPRouteMonitorMessageWithAS4Hint is
// UnmarshalBMPRouteMonitorMessage with an authoritative 4-byte-ASN indicator
// (typically PeerHeader.Is4ByteASN() per RFC 7854 §4.2, i.e. !A): true =
// 4-byte, false = 2-byte. Do not pass the raw A bit.
func UnmarshalBMPRouteMonitorMessageWithAS4Hint(b []byte, as4 bool) (*RouteMonitor, error) {
	return unmarshalBMPRouteMonitorMessage(b, &as4)
}

func unmarshalBMPRouteMonitorMessage(b []byte, as4hint *bool) (*RouteMonitor, error) {
	if glog.V(6) {
		glog.Infof("BMP Route Monitor Message Raw: %s length: %d", tools.MessageHex(b), len(b))
	}
	rm := RouteMonitor{}
	u, err := getBGPUpdateFromBMPMessage(b, as4hint)
	if err != nil {
		return nil, err
	}
	rm.Update = u

	return &rm, nil
}
