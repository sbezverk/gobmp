package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

// RouteMonitor defines a structure of BMP Route Monitoring message
type RouteMonitor struct {
	Update *bgp.Update
}

// UnmarshalBMPRouteMonitorMessage builds BMP Route Monitor object
func UnmarshalBMPRouteMonitorMessage(b []byte) (*RouteMonitor, error) {
	if glog.V(6) {
		glog.Infof("BMP Route Monitor Message Raw: %s length: %d", tools.MessageHex(b), len(b))
	}
	rm := RouteMonitor{}
	// 16 bytes marker + 2 bytes length + 1 byte type
	if len(b) < 19 {
		return nil, fmt.Errorf("malformed route monitor message: need at least 19 bytes, got %d", len(b))
	}
	p := 0
	// Skip 16 bytes of a marker
	p += 16
	// Validate BGP message length field
	bgpLen := binary.BigEndian.Uint16(b[p : p+2])
	if int(bgpLen) < 19 || int(bgpLen) > len(b) {
		return nil, fmt.Errorf("invalid BGP message length %d (buffer %d bytes)", bgpLen, len(b))
	}
	p += 2
	t := b[p]
	p++
	switch t {
	case 2:
		u, err := bgp.UnmarshalBGPUpdate(b[p:])
		if err != nil {
			return nil, err
		}
		rm.Update = u
	default:
		return nil, fmt.Errorf("unexpected BGP message type %d in route monitor (expected 2/Update)", t)
	}

	return &rm, nil
}
