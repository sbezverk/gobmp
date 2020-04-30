package bmp

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// RouteMonitor defines a structure of BMP Route Monitoring message
type RouteMonitor struct {
	Update *bgp.Update
}

// UnmarshalBMPRouteMonitorMessage builds BMP Route Monitor object
func UnmarshalBMPRouteMonitorMessage(b []byte) (*RouteMonitor, error) {
	glog.V(6).Infof("BMP Route Monitor Message Raw: %s", tools.MessageHex(b))
	rm := RouteMonitor{}
	p := 0
	// Skip 16 bytes of a marker
	p += 16
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	u, err := bgp.UnmarshalBGPUpdate(b[p+1 : p+int(l-18)])
	if err != nil {
		return nil, err
	}
	rm.Update = u

	return &rm, nil
}
