package te

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// nodeTLV represents a TLV pair for building Node Descriptors
type nodeTLV struct {
	Type  uint16
	Value []byte
}

// buildNodeDescriptor builds a Node Descriptor with the given TLVs.
func buildNodeDescriptor(descriptorType uint16, tlvs ...nodeTLV) []byte {
	body := []byte{}
	for _, tlv := range tlvs {
		t := make([]byte, 4)
		binary.BigEndian.PutUint16(t[0:2], tlv.Type)
		binary.BigEndian.PutUint16(t[2:4], uint16(len(tlv.Value)))
		body = append(body, t...)
		body = append(body, tlv.Value...)
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], descriptorType)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(body)))
	return append(header, body...)
}

// buildTEPolicyNLRI builds a complete TE Policy NLRI byte slice.
func buildTEPolicyNLRI(protoID byte, identifier []byte, nodeDesc []byte, policyDesc []byte) []byte {
	b := []byte{protoID}
	b = append(b, identifier...)
	b = append(b, nodeDesc...)
	if policyDesc != nil {
		b = append(b, policyDesc...)
	}
	return b
}

// buildPolicyTLV builds a single TLV for Policy Descriptor.
func buildPolicyTLV(tlvType uint16, value []byte) []byte {
	t := make([]byte, 4)
	binary.BigEndian.PutUint16(t[0:2], tlvType)
	binary.BigEndian.PutUint16(t[2:4], uint16(len(value)))
	return append(t, value...)
}

// asn65000 is a 4-byte ASN value for AS 65000.
var asn65000 = []byte{0x00, 0x00, 0xfd, 0xe8}

// routerID is a 4-byte BGP Router ID (192.168.1.1).
var routerID = []byte{0xc0, 0xa8, 0x01, 0x01}

// identifier is an 8-byte domain identifier.
var identifier = make([]byte, 8)

// validNodeDesc builds a valid Node Descriptor with mandatory TLVs 512 and 516.
func validNodeDesc() []byte {
	return buildNodeDescriptor(256,
		nodeTLV{Type: 512, Value: asn65000},
		nodeTLV{Type: 516, Value: routerID})
}

// --- TE Policy NLRI Parsing Tests ---

func TestTEPolicy_NLRI_SR_ProtocolID(t *testing.T) {
	nd := validNodeDesc()
	input := buildTEPolicyNLRI(0x09, identifier, nd, nil)

	nlri, err := UnmarshalTEPolicyNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.ProtocolID != 9 {
		t.Errorf("ProtocolID = %d, want 9 (SR)", nlri.ProtocolID)
	}
}

func TestTEPolicy_NLRI_RSVPTE_ProtocolID(t *testing.T) {
	nd := validNodeDesc()
	input := buildTEPolicyNLRI(0x08, identifier, nd, nil)

	nlri, err := UnmarshalTEPolicyNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.ProtocolID != 8 {
		t.Errorf("ProtocolID = %d, want 8 (RSVP-TE)", nlri.ProtocolID)
	}
}

func TestTEPolicy_NLRI_InvalidProtocolID(t *testing.T) {
	nd := validNodeDesc()
	tests := []byte{0x00, 0x01, 0x07, 0x0A, 0xFF}
	for _, pid := range tests {
		input := buildTEPolicyNLRI(pid, identifier, nd, nil)
		_, err := UnmarshalTEPolicyNLRI(input)
		if err == nil {
			t.Errorf("expected error for protocol ID %d", pid)
		}
	}
}

func TestTEPolicy_NLRI_EmptyInput(t *testing.T) {
	_, err := UnmarshalTEPolicyNLRI([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestTEPolicy_NLRI_TruncatedIdentifier(t *testing.T) {
	// Protocol ID + only 4 bytes of identifier (need 8)
	input := []byte{0x09, 0x00, 0x00, 0x00, 0x00}
	_, err := UnmarshalTEPolicyNLRI(input)
	if err == nil {
		t.Fatal("expected error for truncated identifier")
	}
}

func TestTEPolicy_NLRI_TruncatedNodeDescriptor(t *testing.T) {
	// Protocol ID + identifier + incomplete node descriptor header
	input := []byte{0x09}
	input = append(input, identifier...)
	input = append(input, 0x01, 0x00) // Node descriptor type but no length
	_, err := UnmarshalTEPolicyNLRI(input)
	if err == nil {
		t.Fatal("expected error for truncated node descriptor")
	}
}

func TestTEPolicy_NLRI_IdentifierCopied(t *testing.T) {
	nd := validNodeDesc()
	id := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	input := buildTEPolicyNLRI(0x09, id, nd, nil)

	nlri, err := UnmarshalTEPolicyNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(nlri.Identifier, id) {
		t.Errorf("Identifier = %v, want %v", nlri.Identifier, id)
	}
}

func TestTEPolicy_NLRI_HeadEndHash(t *testing.T) {
	nd := validNodeDesc()
	input := buildTEPolicyNLRI(0x09, identifier, nd, nil)

	nlri, err := UnmarshalTEPolicyNLRI(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nlri.HeadEndHash == "" {
		t.Error("HeadEndHash should not be empty")
	}
	if len(nlri.HeadEndHash) != 32 {
		t.Errorf("HeadEndHash length = %d, want 32 hex chars", len(nlri.HeadEndHash))
	}
}

func TestTEPolicy_PolicyDescriptor_Standalone(t *testing.T) {
	tunnelID := make([]byte, 2)
	binary.BigEndian.PutUint16(tunnelID, 100)
	pd := buildPolicyTLV(TunnelIDType, tunnelID)

	pdOnly, err := UnmarshalPolicyDescriptor(pd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pdOnly == nil {
		t.Fatal("Policy should not be nil")
	}
	if !pdOnly.Exists(TunnelIDType) {
		t.Error("TunnelID should exist")
	}
}

func TestTEPolicy_NLRI_SingleByteInput(t *testing.T) {
	_, err := UnmarshalTEPolicyNLRI([]byte{0x09})
	if err == nil {
		t.Fatal("expected error for single byte input")
	}
}

// --- Policy Descriptor Tests ---

func TestTEPolicy_PolicyDescriptor_SingleTLV(t *testing.T) {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, 42)
	input := buildPolicyTLV(TunnelIDType, value)

	pd, err := UnmarshalPolicyDescriptor(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pd.TLV) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(pd.TLV))
	}
	if !pd.Exists(TunnelIDType) {
		t.Error("TunnelIDType should exist")
	}
}

func TestTEPolicy_PolicyDescriptor_MultipleTLVs(t *testing.T) {
	tunnelID := make([]byte, 2)
	binary.BigEndian.PutUint16(tunnelID, 100)
	lspID := make([]byte, 2)
	binary.BigEndian.PutUint16(lspID, 200)
	headEnd := []byte{10, 0, 0, 1}

	input := buildPolicyTLV(TunnelIDType, tunnelID)
	input = append(input, buildPolicyTLV(LSPIDType, lspID)...)
	input = append(input, buildPolicyTLV(TunnelHeadEndAddrType, headEnd)...)

	pd, err := UnmarshalPolicyDescriptor(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pd.TLV) != 3 {
		t.Fatalf("expected 3 TLVs, got %d", len(pd.TLV))
	}

	ids := pd.GetAllTLVIDs()
	if len(ids) != 3 {
		t.Errorf("GetAllTLVIDs() returned %d, want 3", len(ids))
	}
}

func TestTEPolicy_PolicyDescriptor_DuplicateTLV(t *testing.T) {
	value1 := make([]byte, 2)
	binary.BigEndian.PutUint16(value1, 100)
	value2 := make([]byte, 2)
	binary.BigEndian.PutUint16(value2, 200)

	input := buildPolicyTLV(TunnelIDType, value1)
	input = append(input, buildPolicyTLV(TunnelIDType, value2)...)

	pd, err := UnmarshalPolicyDescriptor(input)
	if err != nil {
		t.Fatalf("unexpected error when parsing duplicate TLVs: %v", err)
	}

	if !pd.Exists(TunnelIDType) {
		t.Error("expected TunnelIDType to exist in Policy Descriptor with duplicate TLVs")
	}
	if len(pd.TLV) == 0 {
		t.Error("expected at least one TLV to be stored for duplicate TunnelIDType")
	}
}

func TestTEPolicy_PolicyDescriptor_TruncatedTLVHeader(t *testing.T) {
	// Only 3 bytes (need 4 for TLV header)
	_, err := UnmarshalPolicyDescriptor([]byte{0x02, 0x26, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated TLV header")
	}
}

func TestTEPolicy_PolicyDescriptor_TruncatedTLVValue(t *testing.T) {
	input := []byte{
		0x02, 0x26, // Type 550
		0x00, 0x04, // Length 4
		0x00, 0x01, // Only 2 bytes (need 4)
	}
	_, err := UnmarshalPolicyDescriptor(input)
	if err == nil {
		t.Fatal("expected error for truncated TLV value")
	}
}

func TestTEPolicy_PolicyDescriptor_ExistsFalse(t *testing.T) {
	value := make([]byte, 2)
	input := buildPolicyTLV(TunnelIDType, value)

	pd, err := UnmarshalPolicyDescriptor(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pd.Exists(LSPIDType) {
		t.Error("LSPIDType should not exist")
	}
}

// --- TLV Getter Tests ---

func TestTEPolicy_GetTunnelID(t *testing.T) {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, 12345)
	input := buildPolicyTLV(TunnelIDType, value)

	pd, err := UnmarshalPolicyDescriptor(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	id, err := pd.GetTunnelID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 12345 {
		t.Errorf("TunnelID = %d, want 12345", id)
	}
}

func TestTEPolicy_GetTunnelID_Missing(t *testing.T) {
	input := buildPolicyTLV(LSPIDType, make([]byte, 2))
	pd, _ := UnmarshalPolicyDescriptor(input)

	id, err := pd.GetTunnelID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 0 {
		t.Errorf("TunnelID = %d, want 0 when missing", id)
	}
}

func TestTEPolicy_GetTunnelID_InvalidLength(t *testing.T) {
	input := buildPolicyTLV(TunnelIDType, []byte{0x00, 0x01, 0x02}) // 3 bytes, need 2
	pd, _ := UnmarshalPolicyDescriptor(input)

	_, err := pd.GetTunnelID()
	if err == nil {
		t.Fatal("expected error for invalid TunnelID length")
	}
}

func TestTEPolicy_GetLSPID(t *testing.T) {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, 999)
	input := buildPolicyTLV(LSPIDType, value)

	pd, _ := UnmarshalPolicyDescriptor(input)
	id, err := pd.GetLSPID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 999 {
		t.Errorf("LSPID = %d, want 999", id)
	}
}

func TestTEPolicy_GetLSPID_Missing(t *testing.T) {
	input := buildPolicyTLV(TunnelIDType, make([]byte, 2))
	pd, _ := UnmarshalPolicyDescriptor(input)

	id, err := pd.GetLSPID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != 0 {
		t.Errorf("LSPID = %d, want 0 when missing", id)
	}
}

func TestTEPolicy_GetLSPID_InvalidLength(t *testing.T) {
	input := buildPolicyTLV(LSPIDType, []byte{0x00})
	pd, _ := UnmarshalPolicyDescriptor(input)

	_, err := pd.GetLSPID()
	if err == nil {
		t.Fatal("expected error for invalid LSPID length")
	}
}

func TestTEPolicy_GetTunnelHeadEndAddr_IPv4(t *testing.T) {
	addr := []byte{10, 0, 0, 1}
	input := buildPolicyTLV(TunnelHeadEndAddrType, addr)
	pd, _ := UnmarshalPolicyDescriptor(input)

	got, err := pd.GetTunnelHeadEndAddr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, addr) {
		t.Errorf("addr = %v, want %v", got, addr)
	}
}

func TestTEPolicy_GetTunnelHeadEndAddr_IPv6(t *testing.T) {
	addr := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	input := buildPolicyTLV(TunnelHeadEndAddrType, addr)
	pd, _ := UnmarshalPolicyDescriptor(input)

	got, err := pd.GetTunnelHeadEndAddr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, addr) {
		t.Error("IPv6 addr mismatch")
	}
}

func TestTEPolicy_GetTunnelHeadEndAddr_Missing(t *testing.T) {
	input := buildPolicyTLV(TunnelIDType, make([]byte, 2))
	pd, _ := UnmarshalPolicyDescriptor(input)

	got, err := pd.GetTunnelHeadEndAddr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil when missing")
	}
}

func TestTEPolicy_GetTunnelHeadEndAddr_InvalidLength(t *testing.T) {
	input := buildPolicyTLV(TunnelHeadEndAddrType, make([]byte, 8))
	pd, _ := UnmarshalPolicyDescriptor(input)

	_, err := pd.GetTunnelHeadEndAddr()
	if err == nil {
		t.Fatal("expected error for 8-byte addr (not 4 or 16)")
	}
}

func TestTEPolicy_GetTunnelTailEndAddr_IPv4(t *testing.T) {
	addr := []byte{172, 16, 0, 1}
	input := buildPolicyTLV(TunnelTailEndAddrType, addr)
	pd, _ := UnmarshalPolicyDescriptor(input)

	got, err := pd.GetTunnelTailEndAddr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, addr) {
		t.Errorf("addr = %v, want %v", got, addr)
	}
}

func TestTEPolicy_GetTunnelTailEndAddr_Missing(t *testing.T) {
	input := buildPolicyTLV(TunnelIDType, make([]byte, 2))
	pd, _ := UnmarshalPolicyDescriptor(input)

	got, err := pd.GetTunnelTailEndAddr()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Error("expected nil when missing")
	}
}

func TestTEPolicy_GetTunnelTailEndAddr_InvalidLength(t *testing.T) {
	input := buildPolicyTLV(TunnelTailEndAddrType, make([]byte, 6))
	pd, _ := UnmarshalPolicyDescriptor(input)

	_, err := pd.GetTunnelTailEndAddr()
	if err == nil {
		t.Fatal("expected error for 6-byte addr (not 4 or 16)")
	}
}

// --- PolicyCandidatePathDescriptor Tests ---

func TestTEPolicy_CandidatePath_IPv4_BGPSRPolicy(t *testing.T) {
	// 24 bytes: proto(1) + flags(1) + reserved(1) + endpoint(4) + color(4) + asn(4) + origAddr(4) + disc(4) = 23?
	// Actually: proto(1) + flags+reserved(2) + endpoint(4) + color(4) + asn(4) + origAddr(4) + disc(4) = 23
	// But valid lengths are 24, 36, 48. Let's build 24-byte (IPv4 endpoint, IPv4 originator, FlagE=0, FlagO=0)
	b := make([]byte, 24)
	b[0] = byte(BGPSRPolicy)              // Protocol Origin
	b[1] = 0x00                            // Flags: E=0, O=0
	b[2] = 0x00                            // Reserved
	copy(b[3:7], []byte{10, 0, 0, 1})     // Endpoint IPv4
	binary.BigEndian.PutUint32(b[7:11], 100)  // Color
	binary.BigEndian.PutUint32(b[11:15], 65000) // Originator ASN
	copy(b[15:19], []byte{192, 168, 1, 1}) // Originator Addr IPv4
	binary.BigEndian.PutUint32(b[19:23], 42)  // Discriminator
	// b[23] = 0 (padding for 24-byte length)

	got, err := UnmarshalPolicyCandidatePathDescriptor(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProtocolOrigin != BGPSRPolicy {
		t.Errorf("ProtocolOrigin = %d, want %d", got.ProtocolOrigin, BGPSRPolicy)
	}
	if got.FlagE {
		t.Error("FlagE should be false for IPv4")
	}
	if got.FlagO {
		t.Error("FlagO should be false for IPv4")
	}
	if !bytes.Equal(got.Endpoint, []byte{10, 0, 0, 1}) {
		t.Errorf("Endpoint = %v, want [10 0 0 1]", got.Endpoint)
	}
	if got.Color != 100 {
		t.Errorf("Color = %d, want 100", got.Color)
	}
	if got.OriginatorASN != 65000 {
		t.Errorf("OriginatorASN = %d, want 65000", got.OriginatorASN)
	}
}

func TestTEPolicy_CandidatePath_IPv6Endpoint(t *testing.T) {
	// 36 bytes: proto(1) + flags(2) + endpoint(16) + color(4) + asn(4) + origAddr(4) + disc(4) = 35
	// FlagE=1, FlagO=0 -> endpoint IPv6, originator IPv4 -> 1+2+16+4+4+4+4 = 35... hmm
	// Valid lengths are 24, 36, 48
	// 36 = 1+2+16+4+4+4+4+1? No, let me re-examine the code:
	// p=0: proto(1), p=1: flags, p+=2 (skip reserved), so p=3
	// FlagE=1: endpoint 16 bytes -> p=19
	// color: 4 -> p=23
	// asn: 4 -> p=27
	// FlagO=0: origAddr 4 -> p=31
	// disc: 4 -> p=35
	// That's 35 bytes accessed but length must be 36. b[35] would be accessed for disc.
	// Actually disc = b[p:p+4] = b[31:35], that's fine for 36-byte input.
	b := make([]byte, 36)
	b[0] = byte(BGPSRPolicy)
	b[1] = 0x80 // FlagE=1, FlagO=0
	b[2] = 0x00
	ep := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	copy(b[3:19], ep)
	binary.BigEndian.PutUint32(b[19:23], 200) // Color
	binary.BigEndian.PutUint32(b[23:27], 65000) // ASN
	copy(b[27:31], []byte{10, 0, 0, 1}) // Orig Addr IPv4
	binary.BigEndian.PutUint32(b[31:35], 99) // Discriminator

	got, err := UnmarshalPolicyCandidatePathDescriptor(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.FlagE {
		t.Error("FlagE should be true")
	}
	if !bytes.Equal(got.Endpoint, ep) {
		t.Error("IPv6 endpoint mismatch")
	}
	if got.Color != 200 {
		t.Errorf("Color = %d, want 200", got.Color)
	}
}

func TestTEPolicy_CandidatePath_IPv6Originator(t *testing.T) {
	// FlagE=0, FlagO=1 -> endpoint IPv4, originator IPv6
	// 1+2+4+4+4+16+4 = 35 -> need 36 bytes
	b := make([]byte, 36)
	b[0] = byte(PCEP)
	b[1] = 0x40 // FlagE=0, FlagO=1
	b[2] = 0x00
	copy(b[3:7], []byte{10, 0, 0, 1}) // Endpoint IPv4
	binary.BigEndian.PutUint32(b[7:11], 300) // Color
	binary.BigEndian.PutUint32(b[11:15], 65001) // ASN
	origAddr := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	copy(b[15:31], origAddr)
	binary.BigEndian.PutUint32(b[31:35], 77) // Discriminator

	got, err := UnmarshalPolicyCandidatePathDescriptor(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProtocolOrigin != PCEP {
		t.Errorf("ProtocolOrigin = %d, want %d (PCEP)", got.ProtocolOrigin, PCEP)
	}
	if got.FlagO != true {
		t.Error("FlagO should be true")
	}
	if !bytes.Equal(got.OriginatorAddr, origAddr) {
		t.Error("IPv6 originator addr mismatch")
	}
}

func TestTEPolicy_CandidatePath_BothIPv6(t *testing.T) {
	// FlagE=1, FlagO=1 -> both IPv6 -> 1+2+16+4+4+16+4 = 47 -> need 48 bytes
	b := make([]byte, 48)
	b[0] = byte(Local)
	b[1] = 0xC0 // FlagE=1, FlagO=1
	b[2] = 0x00
	ep := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	copy(b[3:19], ep)
	binary.BigEndian.PutUint32(b[19:23], 500)
	binary.BigEndian.PutUint32(b[23:27], 4200000000)
	orig := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
	}
	copy(b[27:43], orig)
	binary.BigEndian.PutUint32(b[43:47], 55)

	got, err := UnmarshalPolicyCandidatePathDescriptor(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ProtocolOrigin != Local {
		t.Errorf("ProtocolOrigin = %d, want %d (Local)", got.ProtocolOrigin, Local)
	}
	if !got.FlagE || !got.FlagO {
		t.Error("both FlagE and FlagO should be true")
	}
	if got.OriginatorASN != 4200000000 {
		t.Errorf("OriginatorASN = %d, want 4200000000", got.OriginatorASN)
	}
}

func TestTEPolicy_CandidatePath_AllProtocolOrigins(t *testing.T) {
	tests := []struct {
		name   string
		origin ProtocolOriginType
	}{
		{"PCEP", PCEP},
		{"BGPSRPolicy", BGPSRPolicy},
		{"Local", Local},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := make([]byte, 24)
			b[0] = byte(tt.origin)
			got, err := UnmarshalPolicyCandidatePathDescriptor(b)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ProtocolOrigin != tt.origin {
				t.Errorf("ProtocolOrigin = %d, want %d", got.ProtocolOrigin, tt.origin)
			}
		})
	}
}

func TestTEPolicy_CandidatePath_InvalidProtocolOrigin(t *testing.T) {
	for _, origin := range []byte{0, 4, 10, 255} {
		b := make([]byte, 24)
		b[0] = origin
		_, err := UnmarshalPolicyCandidatePathDescriptor(b)
		if err == nil {
			t.Errorf("expected error for protocol origin %d", origin)
		}
	}
}

func TestTEPolicy_CandidatePath_InvalidLength(t *testing.T) {
	for _, size := range []int{0, 10, 23, 25, 35, 37, 47, 49, 100} {
		b := make([]byte, size)
		if size > 0 {
			b[0] = byte(BGPSRPolicy)
		}
		_, err := UnmarshalPolicyCandidatePathDescriptor(b)
		if err == nil {
			t.Errorf("expected error for length %d", size)
		}
	}
}

// --- LocalMPLSCrossConnect Tests ---

func TestTEPolicy_LocalMPLSCrossConnect_LabelsOnly(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 1000) // Incoming
	binary.BigEndian.PutUint32(b[4:8], 2000) // Outgoing

	got, err := UnmarshalLocalMPLSCrossConnect(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IncomingLabel != 1000 {
		t.Errorf("IncomingLabel = %d, want 1000", got.IncomingLabel)
	}
	if got.OutgoingLabel != 2000 {
		t.Errorf("OutgoingLabel = %d, want 2000", got.OutgoingLabel)
	}
	if got.SubTLV != nil {
		t.Error("SubTLV should be nil when no sub-TLVs present")
	}
}

func TestTEPolicy_LocalMPLSCrossConnect_TooShort(t *testing.T) {
	_, err := UnmarshalLocalMPLSCrossConnect(make([]byte, 7))
	if err == nil {
		t.Fatal("expected error for input < 8 bytes")
	}
}

func TestTEPolicy_LocalMPLSCrossConnect_WithFECSubTLV(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 100)
	binary.BigEndian.PutUint32(b[4:8], 200)

	// FEC Sub-TLV (type 557): flags(1) + mask(1) + prefix(3) = 5 bytes
	// /24 = 24/8 = 3 bytes for prefix. Validation: p+int(pl) must == len(b) -> 2+3 = 5
	fecValue := []byte{
		0x80,          // Flag4=1 (IPv4)
		0x18,          // Mask length 24
		192, 168, 1,   // 3-byte prefix for /24
	}
	subTLV := buildPolicyTLV(MPLSCrossConnectFECType, fecValue)
	b = append(b, subTLV...)

	got, err := UnmarshalLocalMPLSCrossConnect(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.SubTLV == nil {
		t.Fatal("SubTLV should not be nil")
	}
	if _, ok := got.SubTLV[MPLSCrossConnectFECType]; !ok {
		t.Error("FEC sub-TLV should exist")
	}
}

func TestTEPolicy_LocalMPLSCrossConnect_WithInterfaceSubTLV(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 100)
	binary.BigEndian.PutUint32(b[4:8], 200)

	// Interface Sub-TLV (type 556): flags(1) + ifID(4) + addr(4) = 9 bytes
	ifValue := make([]byte, 9)
	ifValue[0] = 0x80 // FlagI=1
	binary.BigEndian.PutUint32(ifValue[1:5], 42)
	copy(ifValue[5:9], []byte{10, 0, 0, 1})
	subTLV := buildPolicyTLV(MPLSCrossConnectInterfaceType, ifValue)
	b = append(b, subTLV...)

	got, err := UnmarshalLocalMPLSCrossConnect(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got.SubTLV[MPLSCrossConnectInterfaceType]; !ok {
		t.Error("Interface sub-TLV should exist")
	}
}

func TestTEPolicy_LocalMPLSCrossConnect_UnknownSubTLV(t *testing.T) {
	b := make([]byte, 8)
	subTLV := buildPolicyTLV(999, []byte{0x00})
	b = append(b, subTLV...)

	_, err := UnmarshalLocalMPLSCrossConnect(b)
	if err == nil {
		t.Fatal("expected error for unknown sub-TLV type")
	}
}

func TestTEPolicy_LocalMPLSCrossConnect_TruncatedSubTLV(t *testing.T) {
	b := make([]byte, 8)
	// Truncated sub-TLV header (only type, no length)
	b = append(b, 0x02, 0x2D) // type 557 partial
	_, err := UnmarshalLocalMPLSCrossConnect(b)
	if err == nil {
		t.Fatal("expected error for truncated sub-TLV")
	}
}

// --- FEC Sub-TLV Tests ---

func TestTEPolicy_FEC_IPv4(t *testing.T) {
	// /24 = 3 bytes. Validation: p(2) + pl(3) must == len(b)(5)
	b := []byte{
		0x80,         // Flag4=1
		24,           // Mask /24
		192, 168, 1,  // 3-byte prefix
	}
	got, err := UnmarshalLocalMPLSCrossConnectFEC(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Flag4 {
		t.Error("Flag4 should be true")
	}
	if got.Masklength != 24 {
		t.Errorf("Masklength = %d, want 24", got.Masklength)
	}
	// Flag4=true -> Prefix allocated as 4 bytes, copy fills first 3
	if len(got.Prefix) != 4 {
		t.Errorf("Prefix length = %d, want 4 for IPv4", len(got.Prefix))
	}
}

func TestTEPolicy_FEC_IPv6(t *testing.T) {
	// /64 = 8 bytes. p(2) + pl(8) = 10 = len(b)
	b := make([]byte, 10) // flags(1) + mask(1) + prefix(8)
	b[0] = 0x00           // Flag4=0 (IPv6)
	b[1] = 64             // Mask /64
	copy(b[2:], []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00})

	got, err := UnmarshalLocalMPLSCrossConnectFEC(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Flag4 {
		t.Error("Flag4 should be false for IPv6")
	}
	// Flag4=false -> Prefix allocated as 16 bytes
	if len(got.Prefix) != 16 {
		t.Errorf("Prefix length = %d, want 16 for IPv6", len(got.Prefix))
	}
}

func TestTEPolicy_FEC_NonByteAlignedMask(t *testing.T) {
	// /25: (25+7)/8 = 4 bytes. p(2) + pl(4) = 6 = len(b)
	b := []byte{
		0x80,              // Flag4=1
		25,                // Mask /25
		192, 168, 1, 0,    // 4 bytes
	}
	got, err := UnmarshalLocalMPLSCrossConnectFEC(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Masklength != 25 {
		t.Errorf("Masklength = %d, want 25", got.Masklength)
	}
}

func TestTEPolicy_FEC_InvalidLength(t *testing.T) {
	// /24 needs 3 bytes but provide 4 for IPv4 flag
	b := []byte{0x80, 24, 192, 168, 1, 0, 0xFF} // 7 bytes = flags(1)+mask(1)+5 extra, but /24=3 bytes, 2+3=5 != 7
	_, err := UnmarshalLocalMPLSCrossConnectFEC(b)
	if err == nil {
		t.Fatal("expected error for invalid FEC length")
	}
}

func TestTEPolicy_FEC_JSON_RoundTrip(t *testing.T) {
	original := &LocalMPLSCrossConnectFEC{
		Flag4:      true,
		Masklength: 24,
		Prefix:     []byte{192, 168, 1, 0},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(data) == 0 {
		t.Error("marshal produced empty output")
	}

	result := &LocalMPLSCrossConnectFEC{}
	if err := json.Unmarshal(data, result); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if result.Flag4 != original.Flag4 {
		t.Errorf("Flag4 = %v, want %v", result.Flag4, original.Flag4)
	}
	if result.Masklength != original.Masklength {
		t.Errorf("Masklength = %d, want %d", result.Masklength, original.Masklength)
	}
	if !bytes.Equal(result.Prefix, original.Prefix) {
		t.Errorf("Prefix = %v, want %v", result.Prefix, original.Prefix)
	}
}

// --- Interface Sub-TLV Tests ---

func TestTEPolicy_Interface_IPv4(t *testing.T) {
	b := make([]byte, 9)
	b[0] = 0x80 // FlagI=1
	binary.BigEndian.PutUint32(b[1:5], 100)
	copy(b[5:9], []byte{10, 0, 0, 1})

	got, err := UnmarshalLocalMPLSCrossConnectInterface(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.FlagI {
		t.Error("FlagI should be true")
	}
	if got.LocalInterfaceID != 100 {
		t.Errorf("LocalInterfaceID = %d, want 100", got.LocalInterfaceID)
	}
	if !bytes.Equal(got.InterfaceAddr, []byte{10, 0, 0, 1}) {
		t.Errorf("InterfaceAddr = %v, want [10 0 0 1]", got.InterfaceAddr)
	}
}

func TestTEPolicy_Interface_ValidLengths(t *testing.T) {
	b := make([]byte, 23)
	b[0] = 0x00
	binary.BigEndian.PutUint32(b[1:5], 200)
	testAddr := make([]byte, 18)
	copy(b[5:], testAddr)

	got, err := UnmarshalLocalMPLSCrossConnectInterface(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.LocalInterfaceID != 200 {
		t.Errorf("LocalInterfaceID = %d, want 200", got.LocalInterfaceID)
	}
	if len(got.InterfaceAddr) != 18 {
		t.Errorf("InterfaceAddr length = %d, want 18", len(got.InterfaceAddr))
	}
}

func TestTEPolicy_Interface_InvalidLength(t *testing.T) {
	for _, size := range []int{0, 4, 8, 10, 22, 24} {
		b := make([]byte, size)
		_, err := UnmarshalLocalMPLSCrossConnectInterface(b)
		if err == nil {
			t.Errorf("expected error for length %d", size)
		}
	}
}

func TestTEPolicy_Interface_JSON_RoundTrip(t *testing.T) {
	original := &LocalMPLSCrossConnectInterface{
		FlagI:            true,
		LocalInterfaceID: 42,
		InterfaceAddr:    []byte{10, 0, 0, 1},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(data) == 0 {
		t.Error("marshal produced empty output")
	}

	result := &LocalMPLSCrossConnectInterface{}
	if err := json.Unmarshal(data, result); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if result.FlagI != original.FlagI {
		t.Errorf("FlagI = %v, want %v", result.FlagI, original.FlagI)
	}
	if result.LocalInterfaceID != original.LocalInterfaceID {
		t.Errorf("LocalInterfaceID = %d, want %d", result.LocalInterfaceID, original.LocalInterfaceID)
	}
	if !bytes.Equal(result.InterfaceAddr, original.InterfaceAddr) {
		t.Errorf("InterfaceAddr = %v, want %v", result.InterfaceAddr, original.InterfaceAddr)
	}
}

// --- TLV Constant Values ---

func TestTEPolicy_TLVConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		want  uint16
	}{
		{"TunnelIDType", TunnelIDType, 550},
		{"LSPIDType", LSPIDType, 551},
		{"TunnelHeadEndAddrType", TunnelHeadEndAddrType, 552},
		{"TunnelTailEndAddrType", TunnelTailEndAddrType, 553},
		{"PolicyCandidatePathDescriptorType", PolicyCandidatePathDescriptorType, 554},
		{"LocalMPLSCrossConnectType", LocalMPLSCrossConnectType, 555},
		{"MPLSCrossConnectInterfaceType", MPLSCrossConnectInterfaceType, 556},
		{"MPLSCrossConnectFECType", MPLSCrossConnectFECType, 557},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// --- Protocol Origin Constants ---

func TestTEPolicy_ProtocolOriginConstants(t *testing.T) {
	if PCEP != 1 {
		t.Errorf("PCEP = %d, want 1", PCEP)
	}
	if BGPSRPolicy != 2 {
		t.Errorf("BGPSRPolicy = %d, want 2", BGPSRPolicy)
	}
	if Local != 3 {
		t.Errorf("Local = %d, want 3", Local)
	}
}
