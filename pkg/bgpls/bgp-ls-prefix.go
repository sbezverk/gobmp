package bgpls

import (
	"encoding/binary"
	"fmt"
	"net"
)

// GetPrefixIGPFlags returns  IGP Flags
func (ls *NLRI) GetPrefixIGPFlags() (*IGPFlag, error) {
	for _, tlv := range ls.LS {
		if tlv.Type != 1152 {
			continue
		}
		return UnmarshalIGPFlags(tlv.Value)
	}

	return nil, fmt.Errorf("not found")
}

// GetPrefixIGPRouteTag returns a slice of Route Tags
func (ls *NLRI) GetPrefixIGPRouteTag() []uint32 {
	tags := make([]uint32, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1153 {
			continue
		}
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
func (ls *NLRI) GetPrefixIGPExtRouteTag() []uint64 {
	tags := make([]uint64, 0)
	for _, tlv := range ls.LS {
		if tlv.Type != 1154 {
			continue
		}
		for p := 0; p < len(tlv.Value); {
			tag := binary.BigEndian.Uint64(tlv.Value[p : p+8])
			tags = append(tags, tag)
			p += 8
		}
		return tags
	}

	return nil
}

// GetPrefixOSPFForwardAddr returns OSPF Forwarding Address
func (ls *NLRI) GetPrefixOSPFForwardAddr() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1156 {
			continue
		}
		if tlv.Length == 4 {
			return net.IP(tlv.Value).To4().String()
		}
		return net.IP(tlv.Value).To16().String()
	}

	return ""
}
