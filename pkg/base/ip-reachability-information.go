package base

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
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
	s += fmt.Sprintf("      Prefix: %s\n", string(internal.RawBytesToJSON(ipr.Prefix)))

	return s
}

// MarshalJSON defines a method to Marshal IP Reachability Information TLV object into JSON format
func (ipr *IPReachabilityInformation) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"prefixLengthBits\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", ipr.LengthInBits))...)
	jsonData = append(jsonData, []byte("\"\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%s", internal.RawBytesToJSON(ipr.Prefix)))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalIPReachabilityInformation builds IP Reachability Information TLV object
func UnmarshalIPReachabilityInformation(b []byte) (*IPReachabilityInformation, error) {
	glog.V(6).Infof("IPReachabilityInformationTLV Raw: %s", internal.MessageHex(b))
	ipr := IPReachabilityInformation{
		LengthInBits: b[0],
		Prefix:       b[1:],
	}

	return &ipr, nil
}
