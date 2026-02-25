package tunnel

import (
	"encoding/json"
	"testing"
)

// TestRFC9012_TunnelTLVStructure validates the basic TLV structure per RFC 9012 Section 2
func TestRFC9012_TunnelTLVStructure(t *testing.T) {
	tests := []struct {
		name        string
		description string
		input       []byte
		wantType    uint16
		wantLength  uint16
		wantSubTLVs int
	}{
		{
			name:        "SR Policy with single sub-TLV",
			description: "Type 13 (SR Policy) with Preference sub-TLV",
			input:       []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64},
			wantType:    13,
			wantLength:  6,
			wantSubTLVs: 1,
		},
		{
			name:        "SRv6 with multiple sub-TLVs",
			description: "Type 15 (SRv6) with Encapsulation and Color sub-TLVs",
			input: []byte{
				0x00, 0x0f, 0x00, 0x0c, // Type=15, Length=12
				0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, // Sub-TLV Type=1, Len=4
				0x03, 0x04, 0x00, 0x00, 0x00, 0xc8, // Sub-TLV Type=3, Len=4
			},
			wantType:    15,
			wantLength:  12,
			wantSubTLVs: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			te, err := UnmarshalTunnelEncapsulation(tt.input)
			if err != nil {
				t.Fatalf("%s: UnmarshalTunnelEncapsulation() error = %v", tt.description, err)
			}
			if len(te.Tunnels) != 1 {
				t.Fatalf("expected 1 tunnel, got %d", len(te.Tunnels))
			}
			tunnel := te.Tunnels[0]
			if tunnel.Type != tt.wantType {
				t.Errorf("tunnel type = %d, want %d", tunnel.Type, tt.wantType)
			}
			if tunnel.Length != tt.wantLength {
				t.Errorf("tunnel length = %d, want %d", tunnel.Length, tt.wantLength)
			}
			if len(tunnel.SubTLVs) != tt.wantSubTLVs {
				t.Errorf("sub-TLV count = %d, want %d", len(tunnel.SubTLVs), tt.wantSubTLVs)
			}
		})
	}
}

// TestRFC9012_SubTLVLengthEncoding validates 1-octet and 2-octet length encoding per RFC 9012 Section 2
func TestRFC9012_SubTLVLengthEncoding(t *testing.T) {
	tests := []struct {
		name        string
		description string
		input       []byte
		wantType    uint8
		wantLength  uint16
	}{
		{
			name:        "1-octet length (type < 128)",
			description: "Type 1 with 1-octet length field",
			input:       []byte{0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
			wantType:    1,
			wantLength:  4,
		},
		{
			name:        "2-octet length (type >= 128)",
			description: "Type 200 with 2-octet length field",
			input:       []byte{0xc8, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantType:    200,
			wantLength:  8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subTLVs, err := UnmarshalSubTLVs(tt.input)
			if err != nil {
				t.Fatalf("%s: UnmarshalSubTLVs() error = %v", tt.description, err)
			}
			if len(subTLVs) != 1 {
				t.Fatalf("expected 1 sub-TLV, got %d", len(subTLVs))
			}
			if subTLVs[0].Type != tt.wantType {
				t.Errorf("sub-TLV type = %d, want %d", subTLVs[0].Type, tt.wantType)
			}
			if subTLVs[0].Length != tt.wantLength {
				t.Errorf("sub-TLV length = %d, want %d", subTLVs[0].Length, tt.wantLength)
			}
		})
	}
}

// TestRFC9012_TunnelTypes validates common tunnel types from IANA registry
func TestRFC9012_TunnelTypes(t *testing.T) {
	tests := []struct {
		tunnelType uint16
		name       string
	}{
		{1, "L2TPv3 over IP"},
		{2, "GRE"},
		{8, "VXLAN"},
		{9, "NVGRE"},
		{11, "MPLS-in-GRE"},
		{13, "SR Policy"},
		{15, "SRv6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create tunnel TLV with empty sub-TLVs
			input := []byte{
				byte(tt.tunnelType >> 8), byte(tt.tunnelType), // Type
				0x00, 0x00, // Length=0
			}
			te, err := UnmarshalTunnelEncapsulation(input)
			if err != nil {
				t.Fatalf("UnmarshalTunnelEncapsulation() error = %v", err)
			}
			if len(te.Tunnels) != 1 {
				t.Fatalf("expected 1 tunnel, got %d", len(te.Tunnels))
			}
			if te.Tunnels[0].Type != tt.tunnelType {
				t.Errorf("tunnel type = %d, want %d", te.Tunnels[0].Type, tt.tunnelType)
			}
			if te.Tunnels[0].TypeStr != tt.name {
				t.Errorf("tunnel type name = %s, want %s", te.Tunnels[0].TypeStr, tt.name)
			}
		})
	}
}

// TestRFC9012_SubTLVTypes validates common sub-TLV types from IANA registry
func TestRFC9012_SubTLVTypes(t *testing.T) {
	tests := []struct {
		subTLVType uint8
		name       string
	}{
		{1, "Encapsulation"},
		{2, "Protocol Type"},
		{3, "Color"},
		{4, "Tunnel Egress Endpoint"},
		{6, "UDP Destination Port"},
		{9, "Embedded Label Handling"},
		{12, "Preference"},
		{13, "Binding SID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create sub-TLV with zero length
			input := []byte{tt.subTLVType, 0x00}
			subTLVs, err := UnmarshalSubTLVs(input)
			if err != nil {
				t.Fatalf("UnmarshalSubTLVs() error = %v", err)
			}
			if len(subTLVs) != 1 {
				t.Fatalf("expected 1 sub-TLV, got %d", len(subTLVs))
			}
			if subTLVs[0].Type != tt.subTLVType {
				t.Errorf("sub-TLV type = %d, want %d", subTLVs[0].Type, tt.subTLVType)
			}
			if subTLVs[0].TypeStr != tt.name {
				t.Errorf("sub-TLV type name = %s, want %s", subTLVs[0].TypeStr, tt.name)
			}
		})
	}
}

// TestRFC9012_MultipleTunnels validates multiple tunnel TLVs in single attribute
func TestRFC9012_MultipleTunnels(t *testing.T) {
	// Three tunnels: SR Policy, GRE, SRv6
	input := []byte{
		// Tunnel 1: SR Policy
		0x00, 0x0d, 0x00, 0x02, 0x0c, 0x00,
		// Tunnel 2: GRE
		0x00, 0x02, 0x00, 0x02, 0x01, 0x00,
		// Tunnel 3: SRv6
		0x00, 0x0f, 0x00, 0x02, 0x03, 0x00,
	}

	te, err := UnmarshalTunnelEncapsulation(input)
	if err != nil {
		t.Fatalf("UnmarshalTunnelEncapsulation() error = %v", err)
	}

	if len(te.Tunnels) != 3 {
		t.Fatalf("expected 3 tunnels, got %d", len(te.Tunnels))
	}

	expectedTypes := []uint16{13, 2, 15}
	for i, want := range expectedTypes {
		if te.Tunnels[i].Type != want {
			t.Errorf("tunnel[%d] type = %d, want %d", i, te.Tunnels[i].Type, want)
		}
	}
}

// TestRFC9012_JSONEncoding validates JSON serialization
func TestRFC9012_JSONEncoding(t *testing.T) {
	input := []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64}

	te, err := UnmarshalTunnelEncapsulation(input)
	if err != nil {
		t.Fatalf("UnmarshalTunnelEncapsulation() error = %v", err)
	}

	jsonData, err := json.MarshalIndent(te, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify JSON structure
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	tunnels, ok := result["tunnels"].([]interface{})
	if !ok {
		t.Fatal("JSON missing 'tunnels' field")
	}
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 tunnel in JSON, got %d", len(tunnels))
	}

	tunnel, ok := tunnels[0].(map[string]interface{})
	if !ok {
		t.Fatal("tunnel is not a JSON object")
	}

	// Verify required fields
	requiredFields := []string{"type", "type_name", "length", "sub_tlvs"}
	for _, field := range requiredFields {
		if _, exists := tunnel[field]; !exists {
			t.Errorf("JSON missing required field: %s", field)
		}
	}
}

// TestRFC9012_ErrorHandling validates error cases per RFC 9012 requirements
func TestRFC9012_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		description string
		input       []byte
	}{
		{
			name:        "Malformed tunnel TLV",
			description: "Tunnel TLV with length exceeding attribute data",
			input:       []byte{0x00, 0x0d, 0xff, 0xff, 0x01, 0x02},
		},
		{
			name:        "Malformed sub-TLV",
			description: "Sub-TLV with length exceeding tunnel value",
			input:       []byte{0x00, 0x0d, 0x00, 0x04, 0x0c, 0xff, 0xaa, 0xbb},
		},
		{
			name:        "Incomplete tunnel header",
			description: "Attribute ends mid tunnel TLV header",
			input:       []byte{0x00, 0x0d, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTunnelEncapsulation(tt.input)
			if err == nil {
				t.Errorf("%s: expected error, got nil", tt.description)
			}
		})
	}
}
