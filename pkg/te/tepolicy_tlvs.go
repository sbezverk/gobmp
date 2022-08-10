package te

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// TunnelIDType defines Tunnel ID TLV type
	TunnelIDType = 550
	// LSPIDType defines LSP ID TLV type
	LSPIDType = 551
	// TunnelHeadEndAddrType defines Tunnel's Head-End Address TLV type
	TunnelHeadEndAddrType = 552
	// TunnelTailEndAddrType defines Tunnel's Head-End Address TLV type
	TunnelTailEndAddrType = 553
	// PolicyCandidatePathDescriptorType defines Policy Candidate Path Descriptor TLV type
	PolicyCandidatePathDescriptorType = 554
	// LocalMPLSCrossConnectType defines Local MPLS Cross Connect TLV type
	LocalMPLSCrossConnectType = 555
	// MPLSCrossConnectInterfaceType defines MPLS Cross Connect Interface Sub TLV
	MPLSCrossConnectInterfaceType = 556
	// MPLSCrossConnectFECType defines MPLS Cross Connect FEC Sub TLV
	MPLSCrossConnectFECType = 557
)

// GetTunnelID returns the value of Tunnel ID
func (p *PolicyDescriptor) GetTunnelID() (uint16, error) {
	tlv, ok := p.TLV[TunnelIDType]
	if !ok {
		return 0, nil
	}
	if tlv.Length != 2 {
		return 0, fmt.Errorf("invalid tlv %+v length %d", tlv.Type, tlv.Length)
	}

	return binary.BigEndian.Uint16(tlv.Value), nil
}

// GetLSPID returns the value of LSP ID
func (p *PolicyDescriptor) GetLSPID() (uint16, error) {
	tlv, ok := p.TLV[LSPIDType]
	if !ok {
		return 0, nil
	}
	if tlv.Length != 2 {
		return 0, fmt.Errorf("invalid tlv %+v length %d", tlv.Type, tlv.Length)
	}

	return binary.BigEndian.Uint16(tlv.Value), nil
}

// GetTunnelHeadEndAddr returns the value of Tunnel's Head-End address as a slice of bytes (ipv4 or ipv6)
func (p *PolicyDescriptor) GetTunnelHeadEndAddr() ([]byte, error) {
	tlv, ok := p.TLV[TunnelHeadEndAddrType]
	if !ok {
		return nil, nil
	}
	if tlv.Length != 4 && tlv.Length != 16 {
		return nil, fmt.Errorf("invalid tlv %+v length %d", tlv.Type, tlv.Length)
	}

	return tlv.Value, nil
}

// GetTunnelTailEndAddr returns the value of Tunnel's Head-End address as a slice of bytes (ipv4 or ipv6)
func (p *PolicyDescriptor) GetTunnelTailEndAddr() ([]byte, error) {
	tlv, ok := p.TLV[TunnelTailEndAddrType]
	if !ok {
		return nil, nil
	}
	if tlv.Length != 4 && tlv.Length != 16 {
		return nil, fmt.Errorf("invalid tlv %+v length %d", tlv.Type, tlv.Length)
	}

	return tlv.Value, nil
}

// GetPolicyCandidatePathDescriptor returns PolicyCandidatePathDescriptor object
func (p *PolicyDescriptor) GetPolicyCandidatePathDescriptor() (*PolicyCandidatePathDescriptor, error) {
	tlv, ok := p.TLV[PolicyCandidatePathDescriptorType]
	if !ok {
		return nil, nil
	}

	return UnmarshalPolicyCandidatePathDescriptor(tlv.Value)
}

// ProtocolOriginType defines type of Protocol origin responsible for the instantiation of the path.
type ProtocolOriginType uint8

const (
	// PCEP defines protocol origin of a path instantiated by PCEP
	PCEP ProtocolOriginType = 1
	// BGPSRPolicy defines protocol origin of a path instantiated by BGP SR Policy
	BGPSRPolicy ProtocolOriginType = 2
	// Local  defines protocol origin of a path instantiated by CLI, Yang model through NETCONF, gRPC
	Local ProtocolOriginType = 3
)

// https://tools.ietf.org/html/draft-ietf-idr-te-lsp-distribution-14#section-4.5

// PolicyCandidatePathDescriptor defines Policy Candidate Path Descriptor object
type PolicyCandidatePathDescriptor struct {
	ProtocolOrigin ProtocolOriginType `json:"protocol_origin,omitempty"`
	FlagE          bool               `json:"e_flag"`
	FlagO          bool               `json:"o_flag"`
	Endpoint       []byte             `json:"endpoint,omitempty"`
	Color          uint32             `json:"color,omitempty"`
	OriginatorASN  uint32             `json:"originator_asn,omitempty"`
	OriginatorAddr []byte             `json:"originator_address,omitempty"`
	Descriminator  uint32             `json:"descriminator,omitempty"`
}

// UnmarshalPolicyCandidatePathDescriptor instantiates PolicyCandidatePathDescriptor object from a slice of bytes
func UnmarshalPolicyCandidatePathDescriptor(b []byte) (*PolicyCandidatePathDescriptor, error) {
	if glog.V(6) {
		glog.Infof("TE Policy Descriptor Raw: %s", tools.MessageHex(b))
	}
	switch len(b) {
	case 24:
	case 36:
	case 48:
	default:
		glog.Infof("Policy Candidate Path Descriptor Raw: %s", tools.MessageHex(b))
		return nil, fmt.Errorf("invalid length of bytes %d", len(b))
	}
	pc := &PolicyCandidatePathDescriptor{}
	p := 0
	switch ProtocolOriginType(b[p]) {
	case PCEP:
		pc.ProtocolOrigin = PCEP
	case BGPSRPolicy:
		pc.ProtocolOrigin = BGPSRPolicy
	case Local:
		pc.ProtocolOrigin = Local
	default:
		glog.Infof("Policy Candidate Path Descriptor Raw: %s", tools.MessageHex(b))
		return nil, fmt.Errorf("invalid protocol origin %d", b[p])
	}
	p++
	pc.FlagE = b[p]&0x80 == 0x80
	pc.FlagO = b[p]&0x40 == 0x40
	// Skip reserved 2 bytes
	p += 2
	if pc.FlagE {
		// Endpoint is ipv6 address
		pc.Endpoint = make([]byte, 16)
		copy(pc.Endpoint, b[p:p+16])
		p += 16
	} else {
		// Endpoint is ipv4 address
		pc.Endpoint = make([]byte, 4)
		copy(pc.Endpoint, b[p:p+4])
		p += 4
	}
	pc.Color = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	pc.OriginatorASN = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	if pc.FlagO {
		// Originator Address is ipv6
		pc.OriginatorAddr = make([]byte, 16)
		copy(pc.OriginatorAddr, b[p:p+16])
		p += 16
	} else {
		// Originator Address is ipv4
		pc.OriginatorAddr = make([]byte, 4)
		copy(pc.OriginatorAddr, b[p:p+4])
		p += 4
	}
	pc.Descriminator = binary.BigEndian.Uint32(b[p : p+4])

	return pc, nil
}

// LocalMPLSCrossConnectSubTLV defines interface for Local MPLS Cross Connect Sub TLVs
type LocalMPLSCrossConnectSubTLV interface {
	MarshalJSON() ([]byte, error)
	UnmarshalJSON([]byte) error
}

// LocalMPLSCrossConnect defines an object which identifies a local MPLS state in the
// form of incoming label and interface followed by an outgoing label and interface.
type LocalMPLSCrossConnect struct {
	IncomingLabel uint32                                 `json:"incoming_label"`
	OutgoingLabel uint32                                 `json:"outgoing_label"`
	SubTLV        map[uint16]LocalMPLSCrossConnectSubTLV `json:"subtlv,omitempty"`
}

// UnmarshalLocalMPLSCrossConnect instantiates LocalMPLSCrossConnect object from a slice of bytes
func UnmarshalLocalMPLSCrossConnect(b []byte) (*LocalMPLSCrossConnect, error) {
	if glog.V(6) {
		glog.Infof("Local MPLS Cross Connect Raw: %s", tools.MessageHex(b))
	}
	// LocalMPLSCrossConnect MUST carry Incoming and Outgoing labels, so length must be at minimum of 8 bytes
	if len(b) < 8 {
		glog.Infof("Local MPLS Cross Connect Raw: %s", tools.MessageHex(b))
		return nil, fmt.Errorf("not enough bytes to decode Local MPLS Cross Connect")
	}
	p := 0
	l := &LocalMPLSCrossConnect{}
	l.IncomingLabel = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	l.OutgoingLabel = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	if p < len(b) {
		s, err := UnmarshalLocalMPLSCrossConnectSubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		l.SubTLV = s
	}

	return l, nil
}

// UnmarshalLocalMPLSCrossConnectSubTLV instantiates a slice of LocalMPLSCrossConnect's Sub TLVs
func UnmarshalLocalMPLSCrossConnectSubTLV(b []byte) (map[uint16]LocalMPLSCrossConnectSubTLV, error) {
	if glog.V(6) {
		glog.Infof("Local MPLS Cross Connect Sub TLVs Raw: %s", tools.MessageHex(b))
	}
	s := make(map[uint16]LocalMPLSCrossConnectSubTLV)
	p := 0
	for p < len(b) {
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode Local MPLS Cross Connect Sub TLVs")
		}
		t := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+2 > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode Local MPLS Cross Connect Sub TLVs")
		}
		l := binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		if p+int(l) > len(b) {
			return nil, fmt.Errorf("not enough bytes to decode Local MPLS Cross Connect Sub TLVs")
		}
		var v LocalMPLSCrossConnectSubTLV
		var err error
		switch t {
		case MPLSCrossConnectFECType:
			if v, err = UnmarshalLocalMPLSCrossConnectFEC(b[p : p+int(l)]); err != nil {
				return nil, err
			}
			s[MPLSCrossConnectFECType] = v
		case MPLSCrossConnectInterfaceType:
			if v, err = UnmarshalLocalMPLSCrossConnectInterface(b[p : p+int(l)]); err != nil {
				return nil, err
			}
			s[MPLSCrossConnectInterfaceType] = v
		default:
			return nil, fmt.Errorf("unexpected Local MPLS Cross Connect Sub TLV type %d", t)
		}
		p += int(l)
	}

	return s, nil
}

var _ LocalMPLSCrossConnectSubTLV = &LocalMPLSCrossConnectFEC{}

// LocalMPLSCrossConnectFEC defines Local MPLS Cross Connect FEC Sub TLV
type LocalMPLSCrossConnectFEC struct {
	Flag4      bool   `json:"4_flag"`
	Masklength uint8  `json:"mask_length"`
	Prefix     []byte `json:"prefix"`
}

// UnmarshalLocalMPLSCrossConnectFEC instantiates Local MPLS Cross Connect FEC Sub TLV object
func UnmarshalLocalMPLSCrossConnectFEC(b []byte) (*LocalMPLSCrossConnectFEC, error) {
	if glog.V(6) {
		glog.Infof("Local MPLS Cross Connect FEC Sub TLV Raw: %s", tools.MessageHex(b))
	}
	f := &LocalMPLSCrossConnectFEC{}
	p := 0
	f.Flag4 = b[p]&0x80 == 0x80
	p++
	f.Masklength = b[p]
	p++
	pl := f.Masklength / 8
	if f.Masklength%8 != 0 {
		pl++
	}
	if p+int(pl) != len(b) {
		return nil, fmt.Errorf("invalid length %d to decode Local MPLS Cross Connect FEC Sub TLV", len(b))
	}
	if f.Flag4 {
		f.Prefix = make([]byte, 4)
	} else {
		f.Prefix = make([]byte, 16)
	}
	copy(f.Prefix, b[p:])

	return f, nil
}

// MarshalJSON generates a slice of bytes for Local MPLS Cross Connect FEC Sub TLV object
func (f *LocalMPLSCrossConnectFEC) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flag4      bool   `json:"4_flag"`
		Masklength uint8  `json:"mask_length"`
		Prefix     []byte `json:"prefix"`
	}{
		Flag4:      f.Flag4,
		Masklength: f.Masklength,
		Prefix:     f.Prefix,
	})
}

// UnmarshalJSON instantiates Local MPLS Cross Connect FEC Sub TLV object from a slice of bytes
func (f *LocalMPLSCrossConnectFEC) UnmarshalJSON(b []byte) error {
	t := &LocalMPLSCrossConnectFEC{}
	if err := json.Unmarshal(b, t); err != nil {
		return nil
	}
	f = t

	return nil
}

var _ LocalMPLSCrossConnectSubTLV = &LocalMPLSCrossConnectInterface{}

// LocalMPLSCrossConnectInterface defines Local MPLS Cross Connect Interface Sub TLV
type LocalMPLSCrossConnectInterface struct {
	FlagI            bool   `json:"i_flag"`
	LocalInterfaceID uint32 `json:"local_interface_id"`
	InterfaceAddr    []byte `json:"interface_address"`
}

// UnmarshalLocalMPLSCrossConnectInterface instantiates Local MPLS Cross Connect Interface Sub TLV object
func UnmarshalLocalMPLSCrossConnectInterface(b []byte) (*LocalMPLSCrossConnectInterface, error) {
	if glog.V(6) {
		glog.Infof("Local MPLS Cross Connect Interface Sub TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 9 && len(b) != 23 {
		return nil, fmt.Errorf("invalid length %d to decode Local MPLS Cross Connect Interface Sub TLV", len(b))
	}
	i := &LocalMPLSCrossConnectInterface{}
	p := 0
	i.FlagI = b[p]&0x80 == 0x80
	p++
	i.LocalInterfaceID = binary.BigEndian.Uint32(b[p : p+4])
	p += 4
	switch len(b) - 4 {
	case 4:
		i.InterfaceAddr = make([]byte, 4)
		copy(i.InterfaceAddr, b[p:])
	case 16:
		i.InterfaceAddr = make([]byte, 16)
		copy(i.InterfaceAddr, b[p:])
	}

	return i, nil
}

// MarshalJSON generates a slice of bytes for Local MPLS Cross Connect Interface Sub TLV object
func (i *LocalMPLSCrossConnectInterface) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		FlagI            bool   `json:"i_flag"`
		LocalInterfaceID uint32 `json:"local_interface_id"`
		InterfaceAddr    []byte `json:"interface_address"`
	}{
		FlagI:            i.FlagI,
		LocalInterfaceID: i.LocalInterfaceID,
		InterfaceAddr:    i.InterfaceAddr,
	})
}

// UnmarshalJSON instantiates Local MPLS Cross Connect FEC Sub TLV object from a slice of bytes
func (i *LocalMPLSCrossConnectInterface) UnmarshalJSON(b []byte) error {
	t := &LocalMPLSCrossConnectInterface{}
	if err := json.Unmarshal(b, t); err != nil {
		return nil
	}
	i = t

	return nil
}
