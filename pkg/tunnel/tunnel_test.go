package tunnel

import (
	"encoding/json"
	"testing"
)

func TestUnmarshalTunnelEncapsulation_Valid(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedCount int
		expectedType  uint16
	}{
		{
			name: "Single SR Policy tunnel with Preference sub-TLV",
			// Tunnel Type=13 (SR Policy), Length=6
			// Sub-TLV Type=12 (Preference), Length=4, Value=0x00000064 (100)
			input:         []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64},
			expectedCount: 1,
			expectedType:  TypeSRPolicy,
		},
		{
			name: "GRE tunnel with Encapsulation sub-TLV",
			// Tunnel Type=2 (GRE), Length=8
			// Sub-TLV Type=1 (Encapsulation), Length=6, Value=6 bytes
			input:         []byte{0x00, 0x02, 0x00, 0x08, 0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expectedCount: 1,
			expectedType:  TypeGRE,
		},
		{
			name: "Multiple tunnels",
			// Tunnel 1: Type=13, Length=6, Sub-TLV Type=12, Length=4, Value=100
			// Tunnel 2: Type=2, Length=6, Sub-TLV Type=1, Length=4, Value=4 bytes
			input: []byte{
				0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64,
				0x00, 0x02, 0x00, 0x06, 0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
			},
			expectedCount: 2,
			expectedType:  TypeSRPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			te, err := UnmarshalTunnelEncapsulation(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalTunnelEncapsulation() error = %v", err)
			}
			if len(te.Tunnels) != tt.expectedCount {
				t.Errorf("got %d tunnels, want %d", len(te.Tunnels), tt.expectedCount)
			}
			if len(te.Tunnels) > 0 && te.Tunnels[0].Type != tt.expectedType {
				t.Errorf("first tunnel type = %d, want %d", te.Tunnels[0].Type, tt.expectedType)
			}
		})
	}
}

func TestUnmarshalTunnelEncapsulation_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Empty input",
			input: []byte{},
		},
		{
			name:  "Truncated tunnel TLV header (only 3 bytes)",
			input: []byte{0x00, 0x0d, 0x00},
		},
		{
			name: "Tunnel length exceeds available data",
			// Type=13, Length=100 but only 2 bytes of data
			input: []byte{0x00, 0x0d, 0x00, 0x64, 0xaa, 0xbb},
		},
		{
			name: "Truncated sub-TLV header",
			// Type=13, Length=1, but sub-TLV needs at least 2 bytes
			input: []byte{0x00, 0x0d, 0x00, 0x01, 0x0c},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalTunnelEncapsulation(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestUnmarshalSubTLVs_Valid(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		expectedCount int
		expectedType  uint8
	}{
		{
			name: "Single sub-TLV (1-octet length)",
			// Type=1 (Encapsulation), Length=4, Value=4 bytes
			input:         []byte{0x01, 0x04, 0xaa, 0xbb, 0xcc, 0xdd},
			expectedCount: 1,
			expectedType:  SubTLVEncapsulation,
		},
		{
			name: "Sub-TLV with 2-octet length (type >= 128)",
			// Type=200, Length=0x0010 (16), Value=16 bytes
			input:         []byte{0xc8, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expectedCount: 1,
			expectedType:  200,
		},
		{
			name: "Multiple sub-TLVs",
			// Sub-TLV 1: Type=12, Length=4, Value=0x00000064
			// Sub-TLV 2: Type=3, Length=4, Value=0x000000c8
			input: []byte{
				0x0c, 0x04, 0x00, 0x00, 0x00, 0x64,
				0x03, 0x04, 0x00, 0x00, 0x00, 0xc8,
			},
			expectedCount: 2,
			expectedType:  SubTLVPreference,
		},
		{
			name: "Sub-TLV with zero length",
			// Type=1, Length=0
			input:         []byte{0x01, 0x00},
			expectedCount: 1,
			expectedType:  SubTLVEncapsulation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subTLVs, err := UnmarshalSubTLVs(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalSubTLVs() error = %v", err)
			}
			if len(subTLVs) != tt.expectedCount {
				t.Errorf("got %d sub-TLVs, want %d", len(subTLVs), tt.expectedCount)
			}
			if len(subTLVs) > 0 && subTLVs[0].Type != tt.expectedType {
				t.Errorf("first sub-TLV type = %d, want %d", subTLVs[0].Type, tt.expectedType)
			}
		})
	}
}

func TestUnmarshalSubTLVs_ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Truncated sub-TLV header (only type)",
			input: []byte{0x01},
		},
		{
			name: "Sub-TLV length exceeds available data",
			// Type=1, Length=100 but only 2 bytes of value
			input: []byte{0x01, 0x64, 0xaa, 0xbb},
		},
		{
			name: "2-octet length type but only 1 byte available",
			// Type=200 (requires 2-octet length), but only 1 byte after type
			input: []byte{0xc8, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalSubTLVs(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestTunnelJSON(t *testing.T) {
	// Test JSON marshaling
	input := []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64}
	te, err := UnmarshalTunnelEncapsulation(input)
	if err != nil {
		t.Fatalf("UnmarshalTunnelEncapsulation() error = %v", err)
	}

	jsonData, err := json.Marshal(te)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify JSON is valid and contains expected fields
	var result map[string]interface{}
	if err := json.Unmarshal(jsonData, &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	tunnels, ok := result["tunnels"].([]interface{})
	if !ok || len(tunnels) != 1 {
		t.Errorf("expected 1 tunnel in JSON, got %v", tunnels)
	}
}

func TestGetTunnelTypeName(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{TypeSRPolicy, "SR Policy"},
		{TypeSRv6, "SRv6"},
		{TypeGRE, "GRE"},
		{TypeVXLAN, "VXLAN"},
		{999, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetTunnelTypeName(tt.code)
			if got != tt.want {
				t.Errorf("GetTunnelTypeName(%d) = %s, want %s", tt.code, got, tt.want)
			}
		})
	}
}

func TestGetSubTLVTypeName(t *testing.T) {
	tests := []struct {
		code uint8
		want string
	}{
		{SubTLVEncapsulation, "Encapsulation"},
		{SubTLVPreference, "Preference"},
		{SubTLVColor, "Color"},
		{SubTLVBindingSID, "Binding SID"},
		{255, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := GetSubTLVTypeName(tt.code)
			if got != tt.want {
				t.Errorf("GetSubTLVTypeName(%d) = %s, want %s", tt.code, got, tt.want)
			}
		})
	}
}
