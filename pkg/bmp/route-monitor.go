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

func (rm *RouteMonitor) String() string {
	var s string
	s += rm.Update.String()

	return s
}

// CheckSAFI checks if Route Monitor message carries specified SAFI and returns true or false
func (rm *RouteMonitor) CheckSAFI(safi int) bool {
	for _, pa := range rm.Update.PathAttributes {
		if pa.AttributeType == 0x0e {
			mp, err := bgp.UnmarshalMPReachNLRI(pa.Attribute)
			if err != nil {
				glog.Errorf("failed to unmarshal MP_REACH_NLRI with error: %+v", err)
				return false
			}
			if mp.SubAddressFamilyID == uint8(safi) {
				return true
			}
		}
	}

	return false
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
