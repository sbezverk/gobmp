package multicast

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalMulticastNLRI builds MP NLRI object for multicast routes from the slice of bytes
func UnmarshalMulticastNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Multicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		// Empty NLRI is not an error; callers decide whether it is End-of-RIB (RFC 4724 §2).
		return &base.MPNLRI{}, nil
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, pathID)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}
