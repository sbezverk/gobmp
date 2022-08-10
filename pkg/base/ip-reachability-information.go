package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// IPReachabilityInformation defines IP Reachability TLV
// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
type IPReachabilityInformation struct {
	LengthInBits uint8
	Prefix       []byte
}

// UnmarshalIPReachabilityInformation builds IP Reachability Information TLV object
func UnmarshalIPReachabilityInformation(b []byte) (*IPReachabilityInformation, error) {
	if glog.V(6) {
		glog.Infof("IPReachabilityInformationTLV Raw: %s", tools.MessageHex(b))
	}
	ipr := IPReachabilityInformation{
		LengthInBits: b[0],
	}
	l := ipr.LengthInBits / 8
	if ipr.LengthInBits%8 != 0 {
		l++
	}
	ipr.Prefix = make([]byte, l)
	copy(ipr.Prefix, b[1:])

	return &ipr, nil
}
