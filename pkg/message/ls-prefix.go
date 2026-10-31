package message

import (
	"fmt"
	"net"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// lsPrefixAttrs holds what the BGP-LS Attribute (RFC 9552 §5.3) of an UPDATE
// gives the Prefix NLRI it carries, so it is decoded once for all of them.
type lsPrefixAttrs struct {
	decoded bool
	attr    *bgpls.NLRI
	err     error

	routerID       string
	metric         uint32
	routeTag       []uint32
	igpFlags       *bgpls.IGPFlags
	extRouteTag    []uint64
	flexAlgo       []*bgpls.FlexAlgoPrefixMetric
	srv6Locator    *srv6.LocatorTLV
	opaque         []string
	attrTLVsProto  base.ProtoID
	attrTLVs       *bgpls.PrefixAttrTLVs
	attrTLVsErr    error
	attrTLVsCached bool
}

// get decodes the attribute of update the first time.
func (a *lsPrefixAttrs) get(update *bgp.Update) {
	if a.decoded {
		return
	}
	a.decoded = true
	a.attr, a.err = update.GetBGPLSAttribute()
	if a.err != nil {
		return
	}
	ls := a.attr
	// The router-ID TLV (RFC 9552 Section 5.3.1.4, TLV 1028/1029) is
	// chosen by which TLV is present, not by the prefix NLRI type.
	// Prefer IPv4, fall back to IPv6.
	a.routerID = ls.GetLocalIPv4RouterID()
	if a.routerID == "" {
		a.routerID = ls.GetLocalIPv6RouterID()
	}
	a.metric = ls.GetPrefixMetric()
	a.routeTag = ls.GetPrefixIGPRouteTag()
	if f, err := ls.GetPrefixIGPFlags(); err == nil {
		a.igpFlags = f
	}
	a.extRouteTag = ls.GetPrefixIGPExtRouteTag()
	if fap, err := ls.GetFlexAlgoPrefixMetric(); err == nil {
		a.flexAlgo = fap
	}
	if loc, err := ls.GetLSSRv6Locator(); err == nil {
		a.srv6Locator = loc
	}
	a.opaque = ls.GetOpaquePrefixAttribute()
}

// prefixAttrTLVs returns the Prefix Attribute TLVs for protocol proto, which
// their decoding depends on.
func (a *lsPrefixAttrs) prefixAttrTLVs(proto base.ProtoID) (*bgpls.PrefixAttrTLVs, error) {
	if !a.attrTLVsCached || a.attrTLVsProto != proto {
		a.attrTLVs, a.attrTLVsErr = a.attr.GetPrefixAttrTLVs(proto)
		a.attrTLVsProto, a.attrTLVsCached = proto, true
	}
	return a.attrTLVs, a.attrTLVsErr
}

func (p *producer) lsPrefix(prfx *base.PrefixNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, ipv4 bool) (*LSPrefix, error) {
	return p.lsPrefixShared(prfx, nextHop, op, ph, update, ipv4, &lsPrefixAttrs{})
}

// lsPrefixShared is lsPrefix with the decoded BGP-LS Attribute of update in
// attrs, which the Prefix NLRI of one UPDATE share.
func (p *producer) lsPrefixShared(prfx *base.PrefixNLRI, nextHop string, op int, ph *bmp.PerPeerHeader, update *bgp.Update, ipv4 bool, attrs *lsPrefixAttrs) (*LSPrefix, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}
	msg := LSPrefix{
		Action:     operation,
		RouterHash: ph.Identity.RouterHash,
		RouterIP:   ph.Identity.RouterIP,
		PeerType:   uint8(ph.PeerType),
		PeerHash:   ph.GetPeerHash(),
		PeerASN:    ph.PeerAS,
		Timestamp:  ph.GetPeerTimestamp(),
		DomainID:   prfx.GetIdentifier(),
	}
	if f, err := ph.IsAdjRIBInPost(); err == nil {
		msg.IsAdjRIBInPost = f
	}
	if f, err := ph.IsAdjRIBOutPost(); err == nil {
		msg.IsAdjRIBOutPost = f
	}
	if f, err := ph.IsAdjRIBOut(); err == nil {
		msg.IsAdjRIBOut = f
	}
	if f, err := ph.IsLocRIB(); err == nil {
		msg.IsLocRIB = f
	}
	if f, err := ph.IsLocRIBFiltered(); err == nil {
		msg.IsLocRIBFiltered = f
	}
	// RFC 9069: Set TableName for LocRIB peers
	if msg.IsLocRIB {
		msg.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
	}
	msg.Nexthop = nextHop
	msg.PeerIP = ph.GetPeerAddrString()
	msg.ProtocolID = prfx.ProtocolID
	msg.Protocol = prfx.GetPrefixProtocolID()
	msg.LSID = prfx.GetPrefixLSID()
	msg.LocalNodeHash = prfx.LocalNodeHash
	msg.IGPRouterID = prfx.GetLocalIGPRouterID()
	msg.MTID = prfx.Prefix.GetPrefixMTID()
	route := prfx.Prefix.GetPrefixIPReachability(ipv4)
	if route == nil {
		return nil, fmt.Errorf("no IP reachability TLV for prefix NLRI (ipv4=%v)", ipv4)
	}
	msg.PrefixLen = int32(route.Length)
	pr := route.Prefix
	if !ipv4 {
		if ip := net.IP(pr).To16(); ip != nil {
			msg.Prefix = ip.String()
		}
	} else {
		if ip := net.IP(pr).To4(); ip != nil {
			msg.Prefix = ip.String()
		}
	}
	switch prfx.ProtocolID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		// Proposed by Peter Psenak <ppsenak@cisco.com>
		// 1027 TLV is not sent for ISIS links/prefixes, because ISIS has no
		// concept of areas. The proposal is to use generic representation,
		// so include area-id and always set to 0 for ISIS.
		msg.AreaID = "0"
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		msg.OSPFRouteType = prfx.Prefix.GetPrefixOSPFRouteType()
		msg.AreaID = prfx.LocalNode.GetOSPFAreaID()
	case base.Direct, base.Static, base.BGP, base.RSVPTE, base.SR:
		msg.AreaID = "0"
	default:
		msg.AreaID = "0"
	}
	attrs.get(update)
	if attrs.err == nil {
		msg.RouterID = attrs.routerID
		msg.PrefixMetric = attrs.metric
		msg.IGPRouteTag = attrs.routeTag
		msg.IGPFlags = attrs.igpFlags
		msg.IGPExtRouteTag = attrs.extRouteTag
		if s, err := attrs.prefixAttrTLVs(prfx.ProtocolID); err == nil {
			msg.PrefixAttrTLVs = s
		}
		msg.FlexAlgoPrefixMetric = attrs.flexAlgo
		msg.SRv6Locator = attrs.srv6Locator
		msg.OpaquePrefixAttribute = attrs.opaque
	}

	return &msg, nil
}
