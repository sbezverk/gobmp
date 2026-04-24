package bmp

import (
	"encoding/binary"
	"errors"
	"fmt"

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
	// 16 bytes marker + 2 bytes length + 1 byte type
	if len(b) < 19 {
		return nil, fmt.Errorf("route monitor message too short: need 19 bytes, have %d", len(b))
	}
	p := 0
	// Skip 16 bytes of a marker
	p += 16
	// Validate BGP message length field
	bgpLen := binary.BigEndian.Uint16(b[p : p+2])
	if int(bgpLen) < 19 {
		return nil, fmt.Errorf("invalid BGP message length %d: must be >= 19", bgpLen)
	}
	if int(bgpLen) != len(b) {
		return nil, fmt.Errorf("BGP message length mismatch: header says %d bytes, have %d", bgpLen, len(b))
	}
	p += 2
	t := b[p]
	p++
	switch t {
	case 2:
		var (
			u   *bgp.Update
			err error
		)
		if as4hint != nil {
			u, err = bgp.UnmarshalBGPUpdateWithAS4Hint(b[p:], *as4hint)
		} else {
			u, err = bgp.UnmarshalBGPUpdate(b[p:])
		}
		if err != nil {
			return nil, err
		}
		rm.Update = u
	default:
		return nil, fmt.Errorf("%w: got type %d", ErrNotAnUpdate, t)
	}

	return &rm, nil
}
