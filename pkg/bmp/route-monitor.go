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

// UnmarshalBMPRouteMonitorMessage builds BMP Route Monitor object.
// The optional as4 argument is the BMP Per-Peer Header A flag (RFC 7854 §4.2):
// when provided it overrides the heuristic for 2-byte vs 4-byte AS_PATH encoding.
func UnmarshalBMPRouteMonitorMessage(b []byte, as4 ...bool) (*RouteMonitor, error) {
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
		u, err := bgp.UnmarshalBGPUpdate(b[p:], as4...)
		if err != nil {
			return nil, err
		}
		rm.Update = u
	default:
		return nil, fmt.Errorf("%w: got type %d", ErrNotAnUpdate, t)
	}

	return &rm, nil
}
