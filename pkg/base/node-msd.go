package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// NodeMSD defines Node MSD object
// No RFC yet
type NodeMSD struct {
	MSD []MSDTV
}

func (msd *NodeMSD) String() string {
	var s string
	s += "Node MSD TVs:" + "\n"
	for _, tv := range msd.MSD {
		s += tv.String()
	}

	return s
}

// UnmarshalNodeMSD build Link MSD object
func UnmarshalNodeMSD(b []byte) (*NodeMSD, error) {
	glog.V(6).Infof("Link MSD Raw: %s", internal.MessageHex(b))
	msd := NodeMSD{}
	p := 0
	tvsv, err := UnmarshalMSDTV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	msd.MSD = tvsv

	return &msd, nil
}
