package base

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Route defines a structure of BGP Withdrawn prefix
type Route struct {
	Length uint8
	Prefix []byte
}

func (r *Route) String() string {
	var s string
	s += fmt.Sprintf("prefix length: %d\n", r.Length)
	s += tools.MessageHex(r.Prefix)
	s += "\n"

	return s
}

// UnmarshalRoutes builds BGP Withdrawn routes object
func UnmarshalRoutes(b []byte) ([]Route, error) {
	routes := make([]Route, 0)
	if len(b) == 0 {
		return nil, nil
	}
	glog.V(6).Infof("Routes Raw: %s", tools.MessageHex(b))
	for p := 0; p < len(b); {
		route := Route{}
		route.Length = b[p]
		l := route.Length / 8
		if route.Length%8 != 0 {
			l++
		}
		p++
		route.Prefix = make([]byte, l)
		copy(route.Prefix, b[p:p+int(l)])
		p += int(l)
		routes = append(routes, route)
	}

	return routes, nil
}
