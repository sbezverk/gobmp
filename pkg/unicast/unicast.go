package unicast

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// MPUnicastPrefix defines a single NLRI entry
type MPUnicastPrefix struct {
	Length uint8
	Prefix []byte
}

// MPUnicastNLRI defines a collection of MP Unicast Prefixes recieved in MP_BGP_REACH_NLRI
type MPUnicastNLRI struct {
	NLRI []MPUnicastPrefix
}

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte) (*MPUnicastNLRI, error) {
	glog.V(5).Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	mpnlri := MPUnicastNLRI{
		NLRI: make([]MPUnicastPrefix, 0),
	}

	return &mpnlri, nil
}

// MPLUPrefix defines a single NLRI entry
type MPLUPrefix struct {
	Length uint8
	Label  []*base.Label
	Prefix []byte
}

// MPLUNLRI defines a collection of MP Unicast Prefixes recieved in MP_BGP_REACH_NLRI
type MPLUNLRI struct {
	NLRI []MPLUPrefix
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes
func UnmarshalLUNLRI(b []byte) (*MPLUNLRI, error) {
	glog.V(5).Infof("MP Label Unicast NLRI Raw: %s", tools.MessageHex(b))
	mpnlri := MPLUNLRI{
		NLRI: make([]MPLUPrefix, 0),
	}

	return &mpnlri, nil
}
