package bgpls

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// NLRI defines BGP-LS NLRI object as collection of BGP-LS TLVs
// https://tools.ietf.org/html/rfc7752#section-3.3
type NLRI struct {
	LS []TLV
}

func (ls *NLRI) String() string {
	var s string

	s += "BGP-LS TLVs:" + "\n"
	for _, tlv := range ls.LS {
		s += tlv.String()
	}

	return s
}

// GetMTID returns string of MT-ID TLV containing the array of MT-IDs of all
// topologies where the node is reachable is allowed
func (ls *NLRI) GetMTID() string {
	var s string
	for _, tlv := range ls.LS {
		if tlv.Type != 263 {
			continue
		}
		if len(tlv.Value) == 0 {
			return s
		}
		mit, err := base.UnmarshalMultiTopologyIdentifierTLV(tlv.Value)
		if err != nil {
			return s
		}
		if mit == nil {
			return s
		}
		s += fmt.Sprintf("%d", mit.MTI[0])
		for i := 1; i < len(mit.MTI); i++ {
			s += fmt.Sprintf(",%d", mit.MTI[i])
		}
	}

	return s
}

// GetNodeFlags reeturns Flag Bits TLV carries a bit mask describing node attributes.
func (ls *NLRI) GetNodeFlags() uint8 {
	for _, tlv := range ls.LS {
		if tlv.Type != 1024 {
			continue
		}
		return uint8(tlv.Value[0])
	}
	return 0
}

// GetNodeName returns Value field identifies the symbolic name of the router node
func (ls *NLRI) GetNodeName() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1026 {
			continue
		}
		return string(tlv.Value)
	}
	return ""
}

// GetISISAreaID returns a string IS-IS Area Identifier TLVs
func (ls *NLRI) GetISISAreaID() string {
	var s string
	for _, tlv := range ls.LS {
		if tlv.Type != 1027 {
			continue
		}
		for p := 0; p < len(tlv.Value); {
			s += fmt.Sprintf("%02x.", tlv.Value[p])
			s += fmt.Sprintf("%02x", tlv.Value[p+1])
			s += fmt.Sprintf("%02x", tlv.Value[p+2])
			p += 3
			if p < len(tlv.Value) {
				s += ","
			}
		}
		return s
	}
	return ""
}

// GetNodeIPv4RouterID returns string with local Node IPv4 router ID
func (ls *NLRI) GetNodeIPv4RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1028 {
			continue
		}
		return net.IP(tlv.Value).To4().String()
	}

	return ""
}

// GetNodeIPv6RouterID returns string with local Node IPv6 router ID
func (ls *NLRI) GetNodeIPv6RouterID() string {
	for _, tlv := range ls.LS {
		if tlv.Type != 1029 {
			continue
		}
		return net.IP(tlv.Value).To16().String()
	}

	return ""
}

// GetNodeMSD returns string with Node's MSD codes
func (ls *NLRI) GetNodeMSD() string {
	var s string
	for _, tlv := range ls.LS {
		if tlv.Type != 266 {
			continue
		}
		msd, err := base.UnmarshalNodeMSD(tlv.Value)
		if err != nil {
			return s
		}
		if msd == nil {
			return s
		}
		s += fmt.Sprintf("%d:%d", msd.MSD[0].Type, msd.MSD[0].Value)
		for i := 1; i < len(msd.MSD); i++ {
			s += fmt.Sprintf(",%d:%d", msd.MSD[i].Type, msd.MSD[i].Value)
		}
	}

	return s
}

// GetNodeSRCapabilities returns string representation of SR Capabilities
func (ls *NLRI) GetNodeSRCapabilities() string {
	var s string
	for _, tlv := range ls.LS {
		if tlv.Type != 1034 {
			continue
		}
		cap, err := sr.UnmarshalSRCapability(tlv.Value)
		if err != nil {
			return s
		}
		if cap == nil {
			return s
		}
		s += fmt.Sprintf("%02x ", cap.Flags)
		for _, tlv := range cap.TLV {
			if tlv.SID == nil {
				continue
			}
			s += fmt.Sprintf("%d:%d ", tlv.Range, tlv.SID.Value)
		}
	}

	return s
}

// MarshalJSON defines a method to  BGP-LS TLV object into JSON format
func (ls *NLRI) MarshalJSON() ([]byte, error) {
	var jsonData []byte

	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"BGPLSTLV\":")...)
	jsonData = append(jsonData, '[')
	if ls.LS != nil {
		for i, tlv := range ls.LS {
			b, err := json.Marshal(&tlv)
			if err != nil {
				return nil, err
			}
			jsonData = append(jsonData, b...)
			if i < len(ls.LS)-1 {
				jsonData = append(jsonData, ',')
			}
		}
	}
	jsonData = append(jsonData, ']')
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPLSNLRI builds Prefix NLRI object
func UnmarshalBGPLSNLRI(b []byte) (*NLRI, error) {
	glog.V(6).Infof("BGPLSNLRI Raw: %s", tools.MessageHex(b))
	bgpls := NLRI{}
	ls, err := UnmarshalBGPLSTLV(b)
	if err != nil {
		return nil, err
	}
	bgpls.LS = ls

	return &bgpls, nil
}
