package srpolicycp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

type SRPolicyCandidatePathOrigin uint8

const (
	SRPolicyCandidatePathOriginReserved             SRPolicyCandidatePathOrigin = 0
	SRPolicyCandidatePathOriginPCEP                 SRPolicyCandidatePathOrigin = 1
	SRPolicyCandidatePathOriginBGPSRPolicy          SRPolicyCandidatePathOrigin = 2
	SRPolicyCandidatePathOriginConfiguration        SRPolicyCandidatePathOrigin = 3
	SRPolicyCandidatePathOriginPCEPFromPCE          SRPolicyCandidatePathOrigin = 10
	SRPolicyCandidatePathOriginBGPSRPolicyFromPCE   SRPolicyCandidatePathOrigin = 20
	SRPolicyCandidatePathOriginConfigurationFromPCE SRPolicyCandidatePathOrigin = 30
)

func (o SRPolicyCandidatePathOrigin) String() string {
	switch o {
	case SRPolicyCandidatePathOriginReserved:
		return "Reserved"
	case SRPolicyCandidatePathOriginPCEP:
		return "PCEP"
	case SRPolicyCandidatePathOriginBGPSRPolicy:
		return "BGP SR Policy"
	case SRPolicyCandidatePathOriginConfiguration:
		return "Configuration"
	case SRPolicyCandidatePathOriginPCEPFromPCE:
		return "PCEP from PCE"
	case SRPolicyCandidatePathOriginBGPSRPolicyFromPCE:
		return "BGP SR Policy from PCE"
	case SRPolicyCandidatePathOriginConfigurationFromPCE:
		return "Configuration from PCE"
	default:
		return "Unknown"
	}
}

//	0 1 2 3 4 5 6 7
//
// +-+-+-+-+-+-+-+-+
// |E|O|           |
// +-+-+-+-+-+-+-+-+
type SRPolicyCandidatePathFlags uint8

func (f SRPolicyCandidatePathFlags) IsSetE() bool {
	return f&0x80 != 0
}

func (f SRPolicyCandidatePathFlags) IsSetO() bool {
	return f&0x40 != 0
}

func (f SRPolicyCandidatePathFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		FlagO bool `json:"o_flag"`
		FlagE bool `json:"e_flag"`
	}{
		FlagO: f.IsSetO(),
		FlagE: f.IsSetE(),
	})
}

func (f *SRPolicyCandidatePathFlags) UnmarshalJSON(b []byte) error {
	if f == nil {
		return fmt.Errorf("SRPolicyCandidatePathFlags is nil")
	}
	var aux struct {
		FlagO bool `json:"o_flag"`
		FlagE bool `json:"e_flag"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*f &= 0x00
	if aux.FlagO {
		*f |= 0x40
	}
	if aux.FlagE {
		*f |= 0x80
	}

	return nil
}

// SrPolicyCandidatePathNLRI represents the SR Policy Candidate Path NLRI as defined in RFC 9857, section 3.
// https://www.rfc-editor.org/info/rfc9857/#section-3
type SrPolicyCandidatePathNLRI struct {
	ProtocolID    base.ProtoID
	Identifier    []byte               `json:"domain_id,omitempty"`
	LocalNode     *base.NodeDescriptor `json:"local_node_descriptor,omitempty"`
	Descriptor    *SRPCPDescriptor     `json:"sr_policy_candidate_path_descriptor,omitempty"`
	LocalNodeHash string
}

// UnmarshalSRPolicyCandidatePathNLRI builds SR Policy Candidate Path NLRI object
func UnmarshalSRPolicyCandidatePathNLRI(b []byte) (*SrPolicyCandidatePathNLRI, error) {
	if glog.V(6) {
		glog.Infof("SR Policy Candidate Path NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) < 13 {
		return nil, fmt.Errorf("sr policy candidate path NLRI too short: need at least 13 bytes, have %d", len(b))
	}
	sr := SrPolicyCandidatePathNLRI{}
	p := 0
	sr.ProtocolID = base.ProtoID(b[p])
	if sr.ProtocolID != base.SR {
		return nil, fmt.Errorf("unexpected protocol ID: %v", sr.ProtocolID)
	}
	p++
	sr.Identifier = make([]byte, 8)
	copy(sr.Identifier, b[p:p+8])
	p += 8
	// Get Node Descriptor's length, skip Node Descriptor Type
	l := binary.BigEndian.Uint16(b[p+2 : p+4])
	if p+int(l)+4 > len(b) {
		return nil, fmt.Errorf("sr policy candidate path NLRI truncated at offset %d: need %d bytes for Node Descriptor, have %d", p, int(l)+4, len(b)-p)
	}
	ln, err := base.UnmarshalNodeDescriptor(b[p : p+int(l)+4])
	if err != nil {
		return nil, err
	}
	if ln == nil {
		return nil, fmt.Errorf("local node descriptor is nil")
	}
	if ln.GetLocalNodeIPv4RouterID() == nil && ln.GetLocalNodeIPv6RouterID() == nil {
		return nil, fmt.Errorf("local node descriptor has no valid IPv4 or IPv6 Router ID")
	}
	sr.LocalNode = ln
	lnh := md5.Sum(b[p : p+int(l)+4])
	sr.LocalNodeHash = hex.EncodeToString(lnh[:])
	// Skip Node Descriptor Type and Length 4 bytes
	p += 4
	p += int(l)
	srd, err := UnmarshalSRPCPDescriptor(b[p:])
	if err != nil {
		return nil, err
	}
	sr.Descriptor = srd

	return &sr, nil
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Type              |          Length               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Protocol-Origin|    Flags      |            RESERVED           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Endpoint (4 or 16 octets)                //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Policy Color (4 octets)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |               Originator AS Number (4 octets)                 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |              Originator Address (4 or 16 octets)             //
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Discriminator (4 octets)                   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// SRPCPDescriptor represents the SR Policy Candidate Path Descriptor TLV identifies an SR Policy candidate
// path as defined in [RFC9256]. It is a mandatory TLV for the SR Policy Candidate Path NLRI type.
type SRPCPDescriptor struct {
	ProtoOrigin    SRPolicyCandidatePathOrigin `json:"protocol_origin"`
	Flags          SRPolicyCandidatePathFlags  `json:"flags"`
	Endpoint       netip.Addr                  `json:"endpoint,omitempty"`
	PolicyColor    uint32                      `json:"policy_color,omitempty"`
	OriginatorAS   uint32                      `json:"originator_as,omitempty"`
	OriginatorAddr netip.Addr                  `json:"originator_addr,omitempty"`
	Discriminator  uint32                      `json:"discriminator,omitempty"`
}

// UnmarshalSRPCPDescriptor build SR Policy Candidate Path Descriptor Object
func UnmarshalSRPCPDescriptor(b []byte) (*SRPCPDescriptor, error) {
	if glog.V(6) {
		glog.Infof("SR Policy Candidate Path Descriptor Raw: %s", tools.MessageHex(b))
	}
	srd := SRPCPDescriptor{}
	found := false
	for p := 0; p < len(b); {
		if p+4 > len(b) {
			return nil, fmt.Errorf("sr Policy Candidate Path Descriptor truncated at offset %d: need 4 bytes for TLV header, have %d", p, len(b)-p)
		}
		t := binary.BigEndian.Uint16(b[p : p+2])
		l := binary.BigEndian.Uint16(b[p+2 : p+4])
		if p+4+int(l) > len(b) {
			return nil, fmt.Errorf("sr Policy Candidate Path Descriptor value truncated at offset %d: need %d bytes, have %d", p+4, l, len(b)-p-4)
		}
		value := b[p+4 : p+4+int(l)]
		if t == 554 {
			if l != 24 && l != 36 && l != 48 {
				return nil, fmt.Errorf("invalid SR Policy Candidate Path Descriptor length: %d", l)
			}
			o := 0
			srd.ProtoOrigin = SRPolicyCandidatePathOrigin(value[o])
			o += 1
			srd.Flags = SRPolicyCandidatePathFlags(value[o])
			switch l {
			case 24:
				if srd.Flags.IsSetE() || srd.Flags.IsSetO() {
					return nil, fmt.Errorf("invalid SR Policy Candidate Path Descriptor length 24 with E or O flag set")
				}
			case 36:
				if !srd.Flags.IsSetO() && !srd.Flags.IsSetE() {
					return nil, fmt.Errorf("invalid SR Policy Candidate Path Descriptor length 36 with neither O nor E flag set")
				}
			case 48:
				if !srd.Flags.IsSetE() || !srd.Flags.IsSetO() {
					return nil, fmt.Errorf("invalid SR Policy Candidate Path Descriptor length 48 with E or O flag not set")
				}
			}
			o += 1
			// Skip 2 reserved bytes
			if value[o] != 0 || value[o+1] != 0 {
				return nil, fmt.Errorf("sr Policy Candidate Path Descriptor reserved bytes not zero at offset %d", p+4+o)
			}
			o += 2
			if srd.Flags.IsSetE() {
				if o+16 > len(value) {
					return nil, fmt.Errorf("sr Policy Candidate Path Descriptor endpoint truncated at offset %d: need 16 bytes, have %d", o, len(value)-o)
				}
				srd.Endpoint = netip.AddrFrom16(*(*[16]byte)(value[o : o+16])) // Assuming endpoint is 16 bytes
				o += 16
			} else {
				if o+4 > len(value) {
					return nil, fmt.Errorf("sr Policy Candidate Path Descriptor endpoint truncated at offset %d: need 4 bytes, have %d", o, len(value)-o)
				}
				srd.Endpoint = netip.AddrFrom4(*(*[4]byte)(value[o : o+4]))
				o += 4
			}
			if o+4 > len(value) {
				return nil, fmt.Errorf("sr Policy Candidate Path Descriptor policy color truncated at offset %d: need 4 bytes, have %d", o, len(value)-o)
			}
			srd.PolicyColor = binary.BigEndian.Uint32(value[o : o+4])
			o += 4
			if o+4 > len(value) {
				return nil, fmt.Errorf("sr Policy Candidate Path Descriptor origin AS truncated at offset %d: need 4 bytes, have %d", o, len(value)-o)
			}
			srd.OriginatorAS = binary.BigEndian.Uint32(value[o : o+4])
			o += 4
			if srd.Flags.IsSetO() {
				if o+16 > len(value) {
					return nil, fmt.Errorf("sr Policy Candidate Path Descriptor originator address truncated at offset %d: need 16 bytes, have %d", o, len(value)-o)
				}
				srd.OriginatorAddr = netip.AddrFrom16(*(*[16]byte)(value[o : o+16]))
				o += 16
			} else {
				if o+4 > len(value) {
					return nil, fmt.Errorf("sr Policy Candidate Path Descriptor originator address truncated at offset %d: need 4 bytes, have %d", o, len(value)-o)
				}
				srd.OriginatorAddr = netip.AddrFrom4(*(*[4]byte)(value[o : o+4]))
				o += 4
			}
			srd.Discriminator = binary.BigEndian.Uint32(value[o : o+4])
			found = true
		}
		p += 2      // Type
		p += 2      // Length
		p += int(l) // Actual TLV length
	}

	if !found {
		return nil, fmt.Errorf("not found SR Policy Candidate Path mandatory TLV 554 (SR Policy Candidate Path Descriptor)")
	}

	return &srd, nil
}
