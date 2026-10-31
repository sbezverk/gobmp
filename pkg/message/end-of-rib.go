package message

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// EndOfRIB reports a received marker for one peer, family and monitored RIB.
// It is an observation, not a delivery or commit barrier across broker topics.
type EndOfRIB struct {
	RouterHash       string `json:"router_hash"`
	RouterIP         string `json:"router_ip"`
	PeerHash         string `json:"peer_hash"`
	PeerRD           string `json:"peer_rd"`
	PeerIP           string `json:"peer_ip"`
	RemoteBGPID      string `json:"remote_bgp_id"`
	PeerASN          uint32 `json:"peer_asn"`
	PeerType         uint8  `json:"peer_type"`
	Timestamp        string `json:"timestamp"`
	AFI              uint16 `json:"afi"`
	SAFI             uint8  `json:"safi"`
	IsAdjRIBInPost   bool   `json:"is_adj_rib_in_post_policy"`
	IsAdjRIBOutPost  bool   `json:"is_adj_rib_out_post_policy"`
	IsAdjRIBOut      bool   `json:"is_adj_rib_out"`
	IsLocRIB         bool   `json:"is_loc_rib"`
	IsLocRIBFiltered bool   `json:"is_loc_rib_filtered"`
	TableName        string `json:"table_name,omitempty"`
}

// RFC 4724 §2: the entire UPDATE, rather than an individual empty NLRI,
// determines whether a marker is End-of-RIB.
func endOfRIBFamily(update *bgp.Update) (uint16, uint8, bool) {
	if update == nil || update.WithdrawnRoutesLength != 0 || len(update.WithdrawnRoutes) != 0 || len(update.NLRI) != 0 {
		return 0, 0, false
	}
	if len(update.PathAttributes) == 0 && update.TotalPathAttributeLength == 0 {
		return 1, 1, true
	}
	if len(update.PathAttributes) != 1 {
		return 0, 0, false
	}
	attr := update.PathAttributes[0]
	if attr.AttributeType != bgp.MP_UNREACH_NLRI || len(attr.Attribute) != 3 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(attr.Attribute[:2]), attr.Attribute[2], true
}

func mpFamily(nlri bgp.MPNLRI) (uint16, uint8) {
	switch mp := nlri.(type) {
	case *bgp.MPUnReachNLRI:
		return mp.AddressFamilyID, mp.SubAddressFamilyID
	case *bgp.MPReachNLRI:
		return mp.AddressFamilyID, mp.SubAddressFamilyID
	}
	return 0, 0
}

func (p *producer) produceEndOfRIB(ph *bmp.PerPeerHeader, update *bgp.Update, afi uint16, safi uint8) {
	// Preserve the route-topic records consumed by existing is_eor clients.
	if len(update.PathAttributes) == 0 {
		p.processBGP4Update(ph, update)
	} else if (afi == 1 || afi == 2) && (safi == 1 || safi == 4 || safi == 128 || safi == 85) || afi == 25 && safi == 70 {
		nlri := &bgp.MPUnReachNLRI{AddressFamilyID: afi, SubAddressFamilyID: safi}
		p.processMPUpdate(nlri, DelPrefix, ph, withoutNHC(update))
	}
	marker := EndOfRIB{
		RouterHash: ph.Identity.RouterHash, RouterIP: ph.Identity.RouterIP,
		PeerHash: ph.GetPeerHash(), PeerRD: ph.GetPeerDistinguisherString(),
		PeerIP: ph.GetPeerAddrString(), RemoteBGPID: ph.GetPeerBGPIDString(),
		PeerASN: ph.PeerAS, PeerType: uint8(ph.PeerType), Timestamp: ph.GetPeerTimestamp(), AFI: afi, SAFI: safi,
	}
	marker.IsAdjRIBInPost, _ = ph.IsAdjRIBInPost()
	marker.IsAdjRIBOutPost, _ = ph.IsAdjRIBOutPost()
	marker.IsAdjRIBOut, _ = ph.IsAdjRIBOut()
	marker.IsLocRIB, _ = ph.IsLocRIB()
	marker.IsLocRIBFiltered, _ = ph.IsLocRIBFiltered()
	if marker.IsLocRIB {
		marker.TableName = p.getTableName(ph)
	}
	if err := p.marshalAndPublish(&marker, bmp.EndOfRIBMsg, []byte(marker.RouterHash)); err != nil {
		glog.Errorf("failed to publish End-of-RIB marker: %v", err)
	}
}
