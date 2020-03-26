package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// Capability Defines a structure for BGP Capability TLV which is sent as a part
// Informational TLVs in Open Message
// Known capability codes: https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
// Capability structure: https://tools.ietf.org/html/rfc5492#section-4
type Capability struct {
	Code        uint8
	Length      uint8
	Value       []byte
	Description string
}

func (c *Capability) String() string {
	var s string

	return s
}

// MarshalJSON defines a method to Marshal BGP Capability Information TLV object into JSON format
func (c *Capability) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')

	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalBGPInformationalTLVCapability builds BGP Capability Information TLV object
func UnmarshalBGPInformationalTLVCapability(b []byte) ([]Capability, error) {
	caps := make([]Capability, 0)
	glog.V(6).Infof("BGPInformationalTLVCapability Raw: %s", internal.MessageHex(b))
	for p := 0; p < len(b); {
		cap := Capability{}
		cap.Code = b[p]
		p++
		cap.Length = b[p]
		p++
		cap.Value = make([]byte, cap.Length)
		copy(cap.Value, b[p:p+int(cap.Length)])
		switch cap.Code {
		case 1:
			cap.Description = "MPBGP (1) "
			// According RFC https://tools.ietf.org/html/rfc2858#section-7 Length will always be 4 bytes.
			afi := binary.BigEndian.Uint16(cap.Value[:2])
			safi := cap.Value[3]
			cap.Description += getAFISAFIString(afi, safi)
		// [RFC2858]https://tools.ietf.org/html/rfc2858#section-7
		case 2:
			cap.Description = "Route Refresh (2)"
		case 128:
			cap.Description = "Route Refresh Old (128)"
		// [RFC2918]
		case 3:
			cap.Description = "Outbound Route Filtering"
		// [RFC5291]
		case 5:
			cap.Description = "Extended Next Hop Encoding"
		// [RFC5549]
		case 6:
			cap.Description = "BGP Extended Message"
		// [RFC8654]
		case 7:
			cap.Description = "BGPsec"
		// [RFC8205]
		case 8:
			cap.Description = "Multiple Labels"
		// [RFC8277]
		case 9:
			cap.Description = "BGP Role"
		// [draft-ietf-idr-bgp-open-policy]
		case 64:
			cap.Description = "Graceful Restart"
		// [RFC4724]
		case 65:
			cap.Description = "4 Octet ASN (65)"
		// [RFC6793]
		case 67:
			cap.Description = "Dynamic Capabilities"
		// [draft-ietf-idr-dynamic-cap]
		case 68:
			cap.Description = "Multisession BGP"
		// [draft-ietf-idr-bgp-multisession]
		case 69:
			cap.Description = "ADD-PATH"
		// [RFC7911]
		case 70:
			cap.Description = "Enhanced Route Refresh"
		// [RFC7313]
		case 71:
			cap.Description = "Long-Lived Graceful Restart"
		// [draft-uttaro-idr-bgp-persistence]
		case 73:
			cap.Description = "FQDN"
			// [draft-walton-bgp-hostname-capability]
		default:
			cap.Description = fmt.Sprintf("Unknown bgp capability %d", cap.Code)
		}
		caps = append(caps, cap)
		p += int(cap.Length)
	}

	return caps, nil
}

func getAFISAFIString(afi uint16, safi uint8) string {
	var afiStr, safiStr string
	switch afi {
	case 1:
		afiStr = "IPv4"
	case 2:
		afiStr = "IPv6"
	}
	switch safi {
	case 1:
		safiStr = "Unicast"
	case 2:
		safiStr = "Multicast"
	case 4:
		safiStr = "MPLS Labels"
	case 128:
		safiStr = "MPLS-labeled VPN"
	}

	return fmt.Sprintf(" : afi=%d safi=%d : %s %s ", afi, safi, safiStr, afiStr)
}
