package message

import (
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func (p *producer) mpUnreach(ph *bmp.PerPeerHeader, update *bgp.Update) (interface{}, error) {

	update.GetNLRI15()

	return nil, nil
}
