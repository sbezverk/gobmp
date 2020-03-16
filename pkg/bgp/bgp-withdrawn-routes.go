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

// WithdrawnRoutes defines collection of BGP Withdrawn prefixes
type WithdrawnRoutes struct {
	WithdrawnRoutes []WithdrawnRoute
}

// UnmarshalBGPWithdrawnRoutes builds BGP Withdrawn routes object
func UnmarshalBGPWithdrawnRoutes(b []byte) (*WithdrawnRoutes, error) {
	glog.V(6).Infof("BGPWithdrawnRoutes Raw: %s", internal.MessageHex(b))
	w := WithdrawnRoutes{
		WithdrawnRoutes: make([]WithdrawnRoute, 0),
	}

	return &w, nil
}
