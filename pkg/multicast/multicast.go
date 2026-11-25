package multicast

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalMulticastNLRI builds MP NLRI object for multicast routes (SAFI 2) of
// AFI 2 (ipv6) or 1 from the slice of bytes
func UnmarshalMulticastNLRI(b []byte, pathID bool, ipv6 bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Multicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutesAF(b, pathID, ipv6)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}
