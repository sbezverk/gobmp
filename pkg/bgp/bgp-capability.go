package bgp

import (
	"encoding/binary"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// BGPCapabilities lists registered and active BGP Capabilities as defined in
// https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
var BGPCapabilities = map[uint8]string{
	1:   "Multiprotocol Extensions for BGP-4",
	2:   "Route Refresh Capability for BGP-4",
	3:   "Outbound Route Filtering Capability",
	4:   "Multiple routes to a destination capability (deprecated)",
	5:   "Extended Next Hop Encoding",
	6:   "BGP Extended Message",
	7:   "BGPsec Capability",
	8:   "Multiple Labels Capability",
	9:   "BGP Role (TEMPORARY)",
	64:  "Graceful Restart Capability",
	65:  "Support for 4-octet AS number capability",
	67:  "Support for Dynamic Capability (capability specific)",
	68:  "Multisession BGP Capability",
	69:  "ADD-PATH Capability",
	70:  "Enhanced Route Refresh Capability",
	71:  "Long-Lived Graceful Restart (LLGR) Capability",
	72:  "Routing Policy Distribution",
	73:  "FQDN Capability",
	128: "Prestandard Route Refresh (deprecated)",
	129: "Prestandard Outbound Route Filtering (deprecated)",
	130: "Prestandard Outbound Route Filtering (deprecated)",
	131: "Prestandard Multisession (deprecated)",
	184: "Prestandard FQDN (deprecated)",
	185: "Prestandard OPERATIONAL message (deprecated)",
}

type CapabilityData struct {
	Value       []byte `json:"capability_value,omitempty"`
	Description string `json:"capability_descr,omitempty"`
}

// Capability Defines a structure for BGP Capability TLV which is sent as a part
// Informational TLVs in Open Message
// Known capability codes: https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
// Capability structure: https://tools.ietf.org/html/rfc5492#section-4
type Capability map[uint8][]*CapabilityData

func getAFISAFIString(afi uint16, safi uint8) string {
	var afiStr, safiStr string
	switch afi {
	case 1:
		afiStr = "IPv4"
	case 2:
		afiStr = "IPv6"
	case 16388:
		afiStr = "BGP-LS"
	}
	switch safi {
	case 1:
		safiStr = "Unicast"
	case 2:
		safiStr = "Multicast"
	case 4:
		safiStr = "MPLS Labels"
	case 70:
		safiStr = "BGP EVPN"
	case 71:
		safiStr = "BGP-LS"
	case 72:
		safiStr = "BGP-LS-VPN"
	case 128:
		safiStr = "MPLS-labeled VPN"
	}

	return " : afi=" + strconv.Itoa(int(afi)) + " safi=" + strconv.Itoa(int(safi)) + " " + safiStr + " " + afiStr
}

// UnmarshalBGPCapability builds BGP Capability Information TLV object
func UnmarshalBGPCapability(b []byte) (Capability, error) {
	if glog.V(6) {
		glog.Infof("UnmarshalBGPCapability Raw: %s", tools.MessageHex(b))
	}
	caps := make(Capability)
	for p := 0; p < len(b); {
		code := b[p]
		p++
		length := b[p]
		p++
		capData := &CapabilityData{}
		capData.Value = make([]byte, length)
		copy(capData.Value, b[p:p+int(length)])
		d, ok := BGPCapabilities[code]
		capData.Description = d
		if !ok {
			capData.Description = "Unknown capability " + strconv.Itoa(int(code))
		}
		switch code {
		case 1:
			// According RFC https://tools.ietf.org/html/rfc2858#section-7 Length will always be 4 bytes.
			afi := binary.BigEndian.Uint16(capData.Value[:2])
			safi := capData.Value[3]
			capData.Description += getAFISAFIString(afi, safi)
		}
		c, ok := caps[code]
		if !ok {
			c = make([]*CapabilityData, 0)
		}
		c = append(c, capData)
		caps[code] = c
		p += int(length)
	}

	return caps, nil
}
