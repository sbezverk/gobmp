package bgp

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// WithdrawnRoute defines a structure of BGP Withdrawn prefix
type WithdrawnRoute struct {
	Length uint8
	Prefix []byte
}

func (wr *WithdrawnRoute) String() string {
	var s string
	s += fmt.Sprintf("Withdrawn prefix length: %d\n", wr.Length)
	s += internal.MessageHex(wr.Prefix)
	s += "\n"

	return s
}

// MarshalJSON defines a custom method to convert BGP Update object into JSON object
func (wr *WithdrawnRoute) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, []byte("{\"Length\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", wr.Length))...)
	jsonData = append(jsonData, []byte("\"Prefix\":")...)
	jsonData = append(jsonData, internal.RawBytesToJSON(wr.Prefix)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPWithdrawnRoutes builds BGP Withdrawn routes object
func UnmarshalBGPWithdrawnRoutes(b []byte) ([]WithdrawnRoute, error) {
	glog.V(6).Infof("BGPWithdrawnRoutes Raw: %s", internal.MessageHex(b))
	routes := make([]WithdrawnRoute, 0)
	for p := 0; p < len(b); {
		route := WithdrawnRoute{}
		route.Length = b[p]
		p++
		route.Prefix = make([]byte, route.Length)
		copy(route.Prefix, b[p:p+int(route.Length)])
		p += int(route.Length)
	}

	return routes, nil
}
