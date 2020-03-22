package bmp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// RouteMonitor defines a structure of BMP Route Monitoring message
type RouteMonitor struct {
	Updates []bgp.Update
}

func (rm *RouteMonitor) String() string {
	var s string
	for _, u := range rm.Updates {
		s += u.String()
	}

	return s
}

// CheckSAFI checks if Route Monitor message carries specified SAFI and returns true or false
func (rm *RouteMonitor) CheckSAFI(safi int) bool {
	for _, u := range rm.Updates {
		for _, pa := range u.PathAttributes {
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
	}

	return false
}

// MarshalJSON defines a custom method to convert Route Monitor object into JSON object
func (rm *RouteMonitor) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, []byte("{\"Updates\":")...)
	for i, u := range rm.Updates {
		jsonData = append(jsonData, '[')
		b, err := json.Marshal(&u)
		if err != nil {
			return nil, err
		}
		jsonData = append(jsonData, b...)
		jsonData = append(jsonData, ']')
		if i < len(rm.Updates)-1 {
			jsonData = append(jsonData, ',')
		}
	}
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBMPRouteMonitorMessage builds BMP Route Monitor object
func UnmarshalBMPRouteMonitorMessage(b []byte) (*RouteMonitor, error) {
	glog.V(6).Infof("BMP Route Monitor Message Raw: %s", internal.MessageHex(b))
	rm := RouteMonitor{
		Updates: make([]bgp.Update, 0),
	}
	p := 0
	_, err := UnmarshalPerPeerHeader(b[p : p+42])
	if err != nil {
		return nil, fmt.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
	}
	// Skip Per-Peer header's 42 bytes
	p += 42
	// Skip 16 bytes of a marker
	p += 16
	l := binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	u, err := bgp.UnmarshalBGPUpdate(b[p+1 : p+int(l-18)])
	if err != nil {
		return nil, err
	}
	rm.Updates = append(rm.Updates, *u)
	// p += int(l - 18)

	return &rm, nil
}
