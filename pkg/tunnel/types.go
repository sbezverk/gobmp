package tunnel

// Tunnel Type codes per IANA BGP Tunnel Encapsulation Types Registry
// https://www.iana.org/assignments/bgp-tunnel-encapsulation/
const (
	TypeL2TPv3    uint16 = 1  // L2TPv3 over IP
	TypeGRE       uint16 = 2  // GRE
	TypeVXLAN     uint16 = 8  // VXLAN Encapsulation
	TypeNVGRE     uint16 = 9  // NVGRE Encapsulation
	TypeMPLSinGRE uint16 = 11 // MPLS in GRE
	TypeMPLSinUDP uint16 = 13 // MPLS in UDP Encapsulation (RFC 7510)
	TypeSRPolicy  uint16 = 15 // SR Policy (RFC 9830 §6.2)

	// Deprecated: IANA assigns no "SRv6" tunnel type; 15 is SR Policy.
	// Use TypeSRPolicy.
	TypeSRv6 = TypeSRPolicy
)

// Sub-TLV Type codes per IANA BGP Tunnel Encapsulation Attribute Sub-TLVs Registry
const (
	SubTLVEncapsulation   uint8 = 1  // Encapsulation
	SubTLVProtocolType    uint8 = 2  // Protocol Type
	SubTLVIPsecTunnelAuth uint8 = 3  // IPsec Tunnel Authenticator (DEPRECATED)
	SubTLVColor           uint8 = 4  // Color
	SubTLVEgressEndpoint  uint8 = 6  // Tunnel Egress Endpoint
	SubTLVUDPDestPort     uint8 = 8  // UDP Destination Port
	SubTLVEmbeddedLabel   uint8 = 9  // Embedded Label Handling
	SubTLVPreference      uint8 = 12 // Preference
	SubTLVBindingSID      uint8 = 13 // Binding SID
)

// TunnelTypeNames maps tunnel type codes to human-readable names
var TunnelTypeNames = map[uint16]string{
	TypeL2TPv3:    "L2TPv3 over IP",
	TypeGRE:       "GRE",
	TypeVXLAN:     "VXLAN",
	TypeNVGRE:     "NVGRE",
	TypeMPLSinGRE: "MPLS-in-GRE",
	TypeMPLSinUDP: "MPLS-in-UDP",
	TypeSRPolicy:  "SR Policy",
}

// SubTLVTypeNames maps sub-TLV type codes to human-readable names
var SubTLVTypeNames = map[uint8]string{
	SubTLVEncapsulation:   "Encapsulation",
	SubTLVProtocolType:    "Protocol Type",
	SubTLVIPsecTunnelAuth: "IPsec Tunnel Authenticator (DEPRECATED)",
	SubTLVColor:           "Color",
	SubTLVEgressEndpoint:  "Tunnel Egress Endpoint",
	SubTLVUDPDestPort:     "UDP Destination Port",
	SubTLVEmbeddedLabel:   "Embedded Label Handling",
	SubTLVPreference:      "Preference",
	SubTLVBindingSID:      "Binding SID",

	// Remaining registered codes, named as in the IANA "BGP Tunnel
	// Encapsulation Attribute Sub-TLVs" registry without the "sub-TLV" suffix.
	5:   "Load-Balancing Block",                         // RFC 5640
	7:   "DS Field",                                     // RFC 9012
	10:  "MPLS Label Stack",                             // RFC 9012
	11:  "Prefix-SID",                                   // RFC 9012
	14:  "ENLP",                                         // RFC 9830
	15:  "Priority",                                     // RFC 9830
	16:  "SPI/SI Representation",                        // RFC 9015
	20:  "SRv6 Binding SID",                             // RFC 9830
	64:  "IPSEC-SA-ID",                                  // draft-ietf-idr-sdwan-edge-discovery
	65:  "Extended Port Property",                       // draft-ietf-idr-sdwan-edge-discovery
	66:  "Underlay ISP Properties",                      // draft-ietf-idr-sdwan-edge-discovery
	67:  "IPsec SA Nonce",                               // draft-ietf-idr-sdwan-edge-discovery
	68:  "IPsec Public Key",                             // draft-ietf-idr-sdwan-edge-discovery
	69:  "IPsec SA Proposal",                            // draft-ietf-idr-sdwan-edge-discovery
	70:  "Simplified IPsec SA",                          // draft-ietf-idr-sdwan-edge-discovery
	71:  "IPsec Version",                                // FCFS
	123: "NRP ID",                                       // draft-ietf-idr-sr-policy-nrp
	124: "RPF",                                          // draft-ietf-bess-bgp-multicast-controller
	125: "Tree Label Stack",                             // draft-ietf-bess-bgp-multicast-controller
	128: "Segment List",                                 // RFC 9830
	129: "SR Policy Candidate Path Name",                // RFC 9830
	130: "SR Policy Name",                               // RFC 9830
	131: "Reverse Segment List (TEMPORARY)",             // draft-ietf-idr-sr-policy-path-segment
	192: "The WAN ID",                                   // FCFS
	193: "The Bytes",                                    // FCFS
	194: "IPSEC DIM",                                    // FCFS
	195: "IPSEC Key Exchange",                           // FCFS
	196: "IPSEC SA Proposals",                           // FCFS
	197: "Service Segment List",                         // FCFS
	198: "Service Vtep",                                 // FCFS
	199: "Distributed Etherlink Switch (DES) Adjacency", // FCFS
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
