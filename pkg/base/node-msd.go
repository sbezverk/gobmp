package base

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
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

// MarshalJSON defines a method to Marshal slice of Node MSD TVs into JSON format
func (msd *NodeMSD) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '[')
	if msd.MSD != nil {
		for i, tv := range msd.MSD {
			b, err := json.Marshal(&tv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(msd.MSD)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')

	return jsonData, nil
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
