package bgp

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// Route defines a structure of BGP Withdrawn prefix
type Route struct {
	Length uint8
	Prefix []byte
}

func (r *Route) String() string {
	var s string
	s += fmt.Sprintf("prefix length: %d\n", r.Length)
	s += internal.MessageHex(r.Prefix)
	s += "\n"

	return s
}

// MarshalJSON defines a custom method to convert BGP Update object into JSON object
func (r *Route) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, []byte("{\"Length\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", r.Length))...)
	jsonData = append(jsonData, []byte("\"Prefix\":")...)
	jsonData = append(jsonData, internal.RawBytesToJSON(r.Prefix)...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPRoutes builds BGP Withdrawn routes object
func UnmarshalBGPRoutes(b []byte) ([]Route, error) {
	glog.V(6).Infof("BGPWithdrawnRoutes Raw: %s", internal.MessageHex(b))
	routes := make([]Route, 0)
	for p := 0; p < len(b); {
		route := Route{}
		route.Length = b[p]
		l := route.Length / 8
		p++
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+int(l)])
		p += int(l)
	}

	return routes, nil
}
