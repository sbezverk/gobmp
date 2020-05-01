package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NodeMSD defines Node MSD object
// No RFC yet
type NodeMSD struct {
	MSD []MSDTV
}

// UnmarshalNodeMSD build Link MSD object
func UnmarshalNodeMSD(b []byte) (*NodeMSD, error) {
	glog.V(6).Infof("Node MSD Raw: %s", tools.MessageHex(b))
	msd := NodeMSD{}
	p := 0
	tvsv, err := UnmarshalMSDTV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	msd.MSD = tvsv

	return &msd, nil
}
