package base

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// IPReachabilityInformation defines IP Reachability TLV
// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
type IPReachabilityInformation struct {
	LengthInBits uint8
	Prefix       []byte
}

func (ipr *IPReachabilityInformation) String() string {
	var s string
	s += "   IP Reachability Information:" + "\n"
	s += fmt.Sprintf("      Prefix length in bits: %d\n", ipr.LengthInBits)
	s += fmt.Sprintf("      Prefix: %s\n", string(tools.RawBytesToJSON(ipr.Prefix)))

	return s
}

// UnmarshalIPReachabilityInformation builds IP Reachability Information TLV object
func UnmarshalIPReachabilityInformation(b []byte) (*IPReachabilityInformation, error) {
	glog.V(6).Infof("IPReachabilityInformationTLV Raw: %s", tools.MessageHex(b))
	ipr := IPReachabilityInformation{
		LengthInBits: b[0],
		Prefix:       b[1:],
	}

	return &ipr, nil
}
