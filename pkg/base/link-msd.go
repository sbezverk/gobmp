package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LinkMSD defines Link MSD object
// No RFC yet
type LinkMSD struct {
	MSD []MSDTV
}

// UnmarshalLinkMSD build Link MSD object
func UnmarshalLinkMSD(b []byte) (*LinkMSD, error) {
	glog.V(6).Infof("Link MSD Raw: %s", tools.MessageHex(b))
	msd := LinkMSD{}
	p := 0
	tvsv, err := UnmarshalMSDTV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	msd.MSD = tvsv

	return &msd, nil
}
