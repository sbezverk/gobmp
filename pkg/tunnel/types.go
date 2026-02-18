package tunnel

// Tunnel Type codes per IANA BGP Tunnel Encapsulation Types Registry
// https://www.iana.org/assignments/bgp-tunnel-encapsulation/
const (
	TypeL2TPv3      uint16 = 1  // L2TPv3 over IP
	TypeGRE         uint16 = 2  // GRE
	TypeVXLAN       uint16 = 8  // VXLAN Encapsulation
	TypeNVGRE       uint16 = 9  // NVGRE Encapsulation
	TypeMPLSinGRE   uint16 = 11 // MPLS in GRE
	TypeSRPolicy    uint16 = 13 // SR Policy
	TypeSRv6        uint16 = 15 // Segment Routing with IPv6 Data Plane
)

// Sub-TLV Type codes per IANA BGP Tunnel Encapsulation Attribute Sub-TLVs Registry
const (
	SubTLVEncapsulation      uint8 = 1  // Encapsulation
	SubTLVProtocolType       uint8 = 2  // Protocol Type
	SubTLVColor              uint8 = 3  // Color
	SubTLVEgressEndpoint     uint8 = 4  // Tunnel Egress Endpoint
	SubTLVUDPDestPort        uint8 = 6  // UDP Destination Port
	SubTLVEmbeddedLabel      uint8 = 9  // Embedded Label Handling
	SubTLVPreference         uint8 = 12 // Preference
	SubTLVBindingSID         uint8 = 13 // Binding SID
)

// TunnelTypeNames maps tunnel type codes to human-readable names
var TunnelTypeNames = map[uint16]string{
	TypeL2TPv3:    "L2TPv3 over IP",
	TypeGRE:       "GRE",
	TypeVXLAN:     "VXLAN",
	TypeNVGRE:     "NVGRE",
	TypeMPLSinGRE: "MPLS-in-GRE",
	TypeSRPolicy:  "SR Policy",
	TypeSRv6:      "SRv6",
}

// SubTLVTypeNames maps sub-TLV type codes to human-readable names
var SubTLVTypeNames = map[uint8]string{
	SubTLVEncapsulation:  "Encapsulation",
	SubTLVProtocolType:   "Protocol Type",
	SubTLVColor:          "Color",
	SubTLVEgressEndpoint: "Tunnel Egress Endpoint",
	SubTLVUDPDestPort:    "UDP Destination Port",
	SubTLVEmbeddedLabel:  "Embedded Label Handling",
	SubTLVPreference:     "Preference",
	SubTLVBindingSID:     "Binding SID",
}

// GetTunnelTypeName returns human-readable name for tunnel type code
func GetTunnelTypeName(code uint16) string {
	if name, ok := TunnelTypeNames[code]; ok {
		return name
	}
	return "Unknown"
}

// GetSubTLVTypeName returns human-readable name for sub-TLV type code
func GetSubTLVTypeName(code uint8) string {
	if name, ok := SubTLVTypeNames[code]; ok {
		return name
	}
	return "Unknown"
}
