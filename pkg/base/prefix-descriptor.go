package base

import (
	"encoding/binary"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixDescriptor defines Prefix Descriptor object
// https://tools.ietf.org/html/rfc7752#section-3.2.3
type PrefixDescriptor struct {
	PrefixTLV map[uint16]TLV
}

// GetPrefixMTID returns Multi-Topology identifiers
func (pd *PrefixDescriptor) GetPrefixMTID() []uint16 {
	if tlv, ok := pd.PrefixTLV[263]; ok {
		m, err := UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return nil
		}
		return m.GetMTID()
	}

	return nil
}

// GetPrefixIPReachability returns BGP route struct encoded in Prefix Descriptor TLV
func (pd *PrefixDescriptor) GetPrefixIPReachability(ipv4 bool) *Route {
	if tlv, ok := pd.PrefixTLV[265]; ok {
		routes, err := UnmarshalRoutes(tlv.Value)
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

// GetPrefixIGPFlags returns  IGP Flags
func (pd *PrefixDescriptor) GetPrefixIGPFlags() uint8 {
	if tlv, ok := pd.PrefixTLV[1152]; ok {
		return uint8(tlv.Value[0])
	}
	return 0
}

// GetPrefixOSPFRouteType returns  OSPF Route type
func (pd *PrefixDescriptor) GetPrefixOSPFRouteType() uint8 {
	if tlv, ok := pd.PrefixTLV[264]; ok {
		return uint8(tlv.Value[0])
	}
	return 0
}

// GetPrefixIGPRouteTag returns a slice of Route Tags
func (pd *PrefixDescriptor) GetPrefixIGPRouteTag() []uint32 {
	if tlv, ok := pd.PrefixTLV[1153]; ok {
		tags := make([]uint32, 0)
		for p := 0; p < len(tlv.Value); {
			tag := binary.BigEndian.Uint32(tlv.Value[p : p+4])
			tags = append(tags, tag)
			p += 4
		}
		return tags
	}
	return nil
}

// GetPrefixIGPExtRouteTag returns a slice of Route Tags
func (pd *PrefixDescriptor) GetPrefixIGPExtRouteTag() []uint64 {
	if tlv, ok := pd.PrefixTLV[1154]; ok {
		tags := make([]uint64, 0)
		for p := 0; p < len(tlv.Value); {
			tag := binary.BigEndian.Uint64(tlv.Value[p : p+8])
			tags = append(tags, tag)
			p += 8
		}
		return tags
	}

	return nil
}

// GetPrefixMetric returns  Prefix Metric
func (pd *PrefixDescriptor) GetPrefixMetric() uint32 {
	if tlv, ok := pd.PrefixTLV[1155]; ok {
		return binary.BigEndian.Uint32(tlv.Value[0:4])
	}
	return 0
}

// GetPrefixOSPFForwardAddr returns OSPF Forwarding Address
func (pd *PrefixDescriptor) GetPrefixOSPFForwardAddr() string {
	if tlv, ok := pd.PrefixTLV[1156]; ok {
		if tlv.Length == 4 {
			return net.IP(tlv.Value).To4().String()
		}
		return net.IP(tlv.Value).To16().String()
	}
	return ""
}

// UnmarshalPrefixDescriptor build Prefix Descriptor object
func UnmarshalPrefixDescriptor(b []byte) (*PrefixDescriptor, error) {
	glog.V(6).Infof("PrefixDescriptor Raw: %s", tools.MessageHex(b))
	pd := PrefixDescriptor{}
	p := 0
	ptlv, err := UnmarshalTLV(b[p : p+len(b)])
	if err != nil {
		return nil, err
	}
	pd.PrefixTLV = ptlv

	return &pd, nil
}
