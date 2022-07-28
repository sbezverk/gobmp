package base

import (
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// PrefixDescriptor defines Prefix Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.3
type PrefixDescriptor struct {
	PrefixTLV map[uint16]TLV
}

// GetPrefixMTID returns Multi-Topology identifiers
func (pd *PrefixDescriptor) GetPrefixMTID() *MultiTopologyIdentifier {
	if tlv, ok := pd.PrefixTLV[263]; ok {
		m, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil
		}
		if m == nil {
			return nil
		}
		return m[0]
	}

	return nil
}

// GetPrefixIPReachability returns BGP route struct encoded in Prefix Descriptor TLV
func (pd *PrefixDescriptor) GetPrefixIPReachability(ipv4 bool) *Route {
	if tlv, ok := pd.PrefixTLV[265]; ok {
		// Route incoded in PrefixTLV does not carry Path ID, hence passing "false" to UnmarshalRoutes
		routes, err := UnmarshalRoutes(tlv.Value, false)
		if err != nil {
			return nil
		}
		// Prefix descriptor should carry only a single route, if more than 1 something is wrong
		// returning nil for that case.
		if len(routes) != 1 {
			return nil
		}

		r := Route{
			Length: routes[0].Length,
		}
		if ipv4 {
			r.Prefix = make([]byte, 4)
		} else {
			r.Prefix = make([]byte, 16)
		}
		copy(r.Prefix, routes[0].Prefix)
		return &r
	}
	return nil
}

// GetPrefixOSPFRouteType returns  OSPF Route type
func (pd *PrefixDescriptor) GetPrefixOSPFRouteType() uint8 {
	if tlv, ok := pd.PrefixTLV[264]; ok {
		return uint8(tlv.Value[0])
	}
	return 0
}

// UnmarshalPrefixDescriptor build Prefix Descriptor object
func UnmarshalPrefixDescriptor(b []byte) (*PrefixDescriptor, error) {
	if glog.V(6) {
		glog.Infof("PrefixDescriptor Raw: %s", tools.MessageHex(b))
	}
	pd := PrefixDescriptor{}
	p := 0
	ptlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	pd.PrefixTLV = ptlv

	return &pd, nil
}
