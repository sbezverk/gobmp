package base

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// IPReachabilityInformation defines IP Reachability TLV
// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
type IPReachabilityInformation struct {
	LengthInBits uint8
	Prefix       []byte
}

// UnmarshalIPReachabilityInformation builds IP Reachability Information TLV object.
func UnmarshalIPReachabilityInformation(b []byte) (*IPReachabilityInformation, error) {
	if glog.V(6) {
		glog.Infof("IPReachabilityInformationTLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 1 {
		return nil, fmt.Errorf("invalid IPReachabilityInformationTLV length")
	}
	ipr := IPReachabilityInformation{
		LengthInBits: b[0],
	}
	l := int(ipr.LengthInBits+7) / 8 // ceiling division
	if len(b)-1 < l {
		return nil, fmt.Errorf("IPReachabilityInformation: need %d bytes for prefix, got %d", l, len(b)-1)
	}
	ipr.Prefix = make([]byte, l)
	copy(ipr.Prefix, b[1:1+l])
	return &ipr, nil
}
