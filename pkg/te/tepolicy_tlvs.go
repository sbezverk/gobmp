package te

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
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

// ProtocolOriginType defines type of Protocol origin responsible for the instantiation of the path.
type ProtocolOriginType uint8

const (
	// PCEP defines protocol origin of a path instantiated by PCEP
	PCEP ProtocolOriginType = 1
	// BGPSRPolicy defines protocol origin of a path instantiated by BGP SR Policy
	BGPSRPolicy ProtocolOriginType = 2
	// Local  defines protocol origin of a path instantiated by CLI, Yang model through NETCONF, gRPC
	Local = 3
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

// UnmarshalPolicyCandidatePathDescriptor instantiates PolicyCandidatePathDescriptor obejct from a slice of byytes
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

	return nil, nil
}
