package bgp

import (
	"fmt"

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
