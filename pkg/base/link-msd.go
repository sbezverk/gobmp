package base

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// LinkMSD defines Link MSD object
// No RFC yet
type LinkMSD struct {
	MSD []MSDTV
}

func (msd *LinkMSD) String() string {
	var s string
	s += "Link MSD TVs:" + "\n"
	for _, tv := range msd.MSD {
		s += tv.String()
	}

	return s
}

// MarshalJSON defines a method to Marshal slice of Link MSD TVs into JSON format
func (msd *LinkMSD) MarshalJSON() ([]byte, error) {
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

// UnmarshalLinkMSD build Link MSD object
func UnmarshalLinkMSD(b []byte) (*LinkMSD, error) {
	glog.V(6).Infof("Link MSD Raw: %s", internal.MessageHex(b))
	msd := LinkMSD{}
	p := 0
	tvsv, err := UnmarshalMSDTV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	msd.MSD = tvsv

	return &msd, nil
}
