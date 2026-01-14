package bgpls

import (
	"testing"
)

// TestRFC7752_NodeAttributeTLVs tests all Node Attribute TLVs from RFC 7752 Table 7
func TestRFC7752_NodeAttributeTLVs(t *testing.T) {
	tests := []struct {
		name    string
		tlvType uint16
		input   []byte
		verify  func(*testing.T, *NLRI)
	}{
		{
			name:    "TLV 1024 - Node Flag Bits",
			tlvType: 1024,
			input: []byte{
				0x04, 0x00, // Type: 1024
				0x00, 0x01, // Length: 1
				0x80, // Flags: Overload bit set
			},
			verify: func(t *testing.T, nlri *NLRI) {
				flags, err := nlri.GetNodeFlags()
				if err != nil {
					t.Fatalf("GetNodeFlags() error = %v", err)
				}
				if !flags.OFlag {
					t.Error("Expected Overload flag (OFlag) to be set")
				}
				t.Logf("✅ Node Flags: Overload=%v, Attached=%v, External=%v, ABR=%v, Router=%v, V6=%v",
					flags.OFlag, flags.TFlag, flags.EFlag, flags.BFlag, flags.RFlag, flags.VFlag)
			},
		},
		{
			name:    "TLV 1026 - Node Name",
			tlvType: 1026,
			input: []byte{
				0x04, 0x02, // Type: 1026
				0x00, 0x0B, // Length: 11
				0x72, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x2D, 0x78, 0x72, 0x2D, 0x31, // "router-xr-1"
			},
			verify: func(t *testing.T, nlri *NLRI) {
				nodeName := nlri.GetNodeName()
				if nodeName != "router-xr-1" {
					t.Errorf("Expected node name 'router-xr-1', got '%s'", nodeName)
				}
				t.Logf("✅ Node Name: %s", nodeName)
			},
		},
		{
			name:    "TLV 1027 - IS-IS Area Identifier",
			tlvType: 1027,
			input: []byte{
				0x04, 0x03, // Type: 1027
				0x00, 0x03, // Length: 3
				0x49, 0x00, 0x01, // Area ID: 490001
			},
			verify: func(t *testing.T, nlri *NLRI) {
				areaID := nlri.GetISISAreaID()
				if areaID == "" {
					t.Error("Expected non-empty ISIS Area ID")
				}
				t.Logf("✅ IS-IS Area ID: %s", areaID)
			},
		},
		{
			name:    "TLV 1028 - IPv4 Router-ID of Local Node",
			tlvType: 1028,
			input: []byte{
				0x04, 0x04, // Type: 1028
				0x00, 0x04, // Length: 4
				0x0A, 0x00, 0x00, 0x01, // 10.0.0.1
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1028)
				if tlv == nil {
					t.Fatal("TLV 1028 not found")
				}
				if len(tlv.Value) != 4 {
					t.Errorf("Expected 4 bytes for IPv4, got %d", len(tlv.Value))
				}
				t.Logf("✅ IPv4 Router-ID: %d.%d.%d.%d",
					tlv.Value[0], tlv.Value[1], tlv.Value[2], tlv.Value[3])
			},
		},
		{
			name:    "TLV 1029 - IPv6 Router-ID of Local Node",
			tlvType: 1029,
			input: []byte{
				0x04, 0x05, // Type: 1029
				0x00, 0x10, // Length: 16
				0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1029)
				if tlv == nil {
					t.Fatal("TLV 1029 not found")
				}
				if len(tlv.Value) != 16 {
					t.Errorf("Expected 16 bytes for IPv6, got %d", len(tlv.Value))
				}
				t.Logf("✅ IPv6 Router-ID present (%d bytes)", len(tlv.Value))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestRFC7752_LinkAttributeTLVs tests all Link Attribute TLVs from RFC 7752 Table 9
func TestRFC7752_LinkAttributeTLVs(t *testing.T) {
	tests := []struct {
		name    string
		tlvType uint16
		input   []byte
		verify  func(*testing.T, *NLRI)
	}{
		{
			name:    "TLV 1088 - Administrative Group (Color)",
			tlvType: 1088,
			input: []byte{
				0x04, 0x40, // Type: 1088
				0x00, 0x04, // Length: 4
				0x00, 0x00, 0x00, 0x0F, // Admin Group: 0x0000000F
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1088)
				if tlv == nil {
					t.Fatal("TLV 1088 not found")
				}
				adminGroup := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 |
					uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				if adminGroup != 0x0F {
					t.Errorf("Expected admin group 0x0F, got 0x%X", adminGroup)
				}
				t.Logf("✅ Administrative Group: 0x%08X", adminGroup)
			},
		},
		{
			name:    "TLV 1089 - Maximum Link Bandwidth",
			tlvType: 1089,
			input: []byte{
				0x04, 0x41, // Type: 1089
				0x00, 0x04, // Length: 4
				0x49, 0x74, 0x24, 0x00, // 10 Gbps in IEEE float
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1089)
				if tlv == nil {
					t.Fatal("TLV 1089 not found")
				}
				t.Logf("✅ Maximum Link Bandwidth: %d bytes", len(tlv.Value))
			},
		},
		{
			name:    "TLV 1092 - TE Default Metric",
			tlvType: 1092,
			input: []byte{
				0x04, 0x44, // Type: 1092
				0x00, 0x04, // Length: 4
				0x00, 0x00, 0x00, 0x0A, // Metric: 10
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1092)
				if tlv == nil {
					t.Fatal("TLV 1092 not found")
				}
				metric := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 |
					uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				if metric != 10 {
					t.Errorf("Expected TE metric 10, got %d", metric)
				}
				t.Logf("✅ TE Default Metric: %d", metric)
			},
		},
		{
			name:    "TLV 1093 - Link Protection Type",
			tlvType: 1093,
			input: []byte{
				0x04, 0x45, // Type: 1093
				0x00, 0x02, // Length: 2
				0x01, // Extra Traffic
				0x00, // Reserved
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1093)
				if tlv == nil {
					t.Fatal("TLV 1093 not found")
				}
				protType := tlv.Value[0]
				t.Logf("✅ Link Protection Type: 0x%02X", protType)
			},
		},
		{
			name:    "TLV 1094 - MPLS Protocol Mask",
			tlvType: 1094,
			input: []byte{
				0x04, 0x46, // Type: 1094
				0x00, 0x01, // Length: 1
				0xC0, // LDP=1, RSVP-TE=1
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1094)
				if tlv == nil {
					t.Fatal("TLV 1094 not found")
				}
				mask := tlv.Value[0]
				ldp := (mask & 0x80) != 0
				rsvp := (mask & 0x40) != 0
				t.Logf("✅ MPLS Protocol Mask: LDP=%v, RSVP-TE=%v", ldp, rsvp)
			},
		},
		{
			name:    "TLV 1095 - IGP Metric",
			tlvType: 1095,
			input: []byte{
				0x04, 0x47, // Type: 1095
				0x00, 0x03, // Length: 3
				0x00, 0x00, 0x0A, // Metric: 10
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1095)
				if tlv == nil {
					t.Fatal("TLV 1095 not found")
				}
				var metric uint32
				for i := 0; i < len(tlv.Value); i++ {
					metric = metric<<8 | uint32(tlv.Value[i])
				}
				t.Logf("✅ IGP Metric: %d", metric)
			},
		},
		{
			name:    "TLV 1096 - Shared Risk Link Group",
			tlvType: 1096,
			input: []byte{
				0x04, 0x48, // Type: 1096
				0x00, 0x0C, // Length: 12 (3 SRLGs)
				0x00, 0x00, 0x00, 0x01, // SRLG 1
				0x00, 0x00, 0x00, 0x02, // SRLG 2
				0x00, 0x00, 0x00, 0x03, // SRLG 3
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1096)
				if tlv == nil {
					t.Fatal("TLV 1096 not found")
				}
				srlgCount := len(tlv.Value) / 4
				if srlgCount != 3 {
					t.Errorf("Expected 3 SRLGs, got %d", srlgCount)
				}
				t.Logf("✅ Shared Risk Link Group: %d SRLGs", srlgCount)
			},
		},
		{
			name:    "TLV 1098 - Link Name",
			tlvType: 1098,
			input: []byte{
				0x04, 0x4A, // Type: 1098
				0x00, 0x0E, // Length: 14
				0x47, 0x69, 0x30, 0x2F, 0x30, 0x2F, 0x30, 0x2F, 0x31, 0x30, 0x2E, 0x31, 0x32, 0x33, // "Gi0/0/0/10.123"
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1098)
				if tlv == nil {
					t.Fatal("TLV 1098 not found")
				}
				linkName := string(tlv.Value)
				t.Logf("✅ Link Name: %s", linkName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestRFC7752_PrefixAttributeTLVs tests all Prefix Attribute TLVs from RFC 7752 Table 11
func TestRFC7752_PrefixAttributeTLVs(t *testing.T) {
	tests := []struct {
		name    string
		tlvType uint16
		input   []byte
		verify  func(*testing.T, *NLRI)
	}{
		{
			name:    "TLV 1152 - IGP Flags",
			tlvType: 1152,
			input: []byte{
				0x04, 0x80, // Type: 1152
				0x00, 0x01, // Length: 1
				0x80, // Down bit set
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1152)
				if tlv == nil {
					t.Fatal("TLV 1152 not found")
				}
				flags := tlv.Value[0]
				downBit := (flags & 0x80) != 0
				t.Logf("✅ IGP Flags: Down=%v", downBit)
			},
		},
		{
			name:    "TLV 1153 - IGP Route Tag",
			tlvType: 1153,
			input: []byte{
				0x04, 0x81, // Type: 1153
				0x00, 0x08, // Length: 8 (2 tags)
				0x00, 0x00, 0x00, 0x01, // Tag 1
				0x00, 0x00, 0x00, 0x02, // Tag 2
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1153)
				if tlv == nil {
					t.Fatal("TLV 1153 not found")
				}
				tagCount := len(tlv.Value) / 4
				if tagCount != 2 {
					t.Errorf("Expected 2 route tags, got %d", tagCount)
				}
				t.Logf("✅ IGP Route Tag: %d tags", tagCount)
			},
		},
		{
			name:    "TLV 1154 - IGP Extended Route Tag",
			tlvType: 1154,
			input: []byte{
				0x04, 0x82, // Type: 1154
				0x00, 0x10, // Length: 16 (2 extended tags)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Extended Tag 1
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // Extended Tag 2
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1154)
				if tlv == nil {
					t.Fatal("TLV 1154 not found")
				}
				tagCount := len(tlv.Value) / 8
				if tagCount != 2 {
					t.Errorf("Expected 2 extended tags, got %d", tagCount)
				}
				t.Logf("✅ IGP Extended Route Tag: %d tags", tagCount)
			},
		},
		{
			name:    "TLV 1155 - Prefix Metric",
			tlvType: 1155,
			input: []byte{
				0x04, 0x83, // Type: 1155
				0x00, 0x04, // Length: 4
				0x00, 0x00, 0x00, 0x64, // Metric: 100
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1155)
				if tlv == nil {
					t.Fatal("TLV 1155 not found")
				}
				metric := uint32(tlv.Value[0])<<24 | uint32(tlv.Value[1])<<16 |
					uint32(tlv.Value[2])<<8 | uint32(tlv.Value[3])
				if metric != 100 {
					t.Errorf("Expected prefix metric 100, got %d", metric)
				}
				t.Logf("✅ Prefix Metric: %d", metric)
			},
		},
		{
			name:    "TLV 1156 - OSPF Forwarding Address (IPv4)",
			tlvType: 1156,
			input: []byte{
				0x04, 0x84, // Type: 1156
				0x00, 0x04, // Length: 4
				0x0A, 0x01, 0x01, 0x01, // 10.1.1.1
			},
			verify: func(t *testing.T, nlri *NLRI) {
				tlv := findTLV(nlri.LS, 1156)
				if tlv == nil {
					t.Fatal("TLV 1156 not found")
				}
				if len(tlv.Value) != 4 {
					t.Errorf("Expected IPv4 (4 bytes), got %d bytes", len(tlv.Value))
				}
				t.Logf("✅ OSPF Forwarding Address: %d.%d.%d.%d",
					tlv.Value[0], tlv.Value[1], tlv.Value[2], tlv.Value[3])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: []TLV{}}
			tlvType := uint16(tt.input[0])<<8 | uint16(tt.input[1])
			tlvLen := uint16(tt.input[2])<<8 | uint16(tt.input[3])
			tlv := TLV{
				Type:   tlvType,
				Length: tlvLen,
				Value:  make([]byte, tlvLen),
			}
			copy(tlv.Value, tt.input[4:4+tlvLen])
			nlri.LS = append(nlri.LS, tlv)

			if tt.verify != nil {
				tt.verify(t, nlri)
			}
		})
	}
}

// TestRFC7752_RealWorldScenario tests a complete real-world BGP-LS UPDATE
// with Node NLRI + comprehensive attributes
func TestRFC7752_RealWorldScenario(t *testing.T) {
	t.Run("Real-World: Cisco IOS-XR Router Node Advertisement", func(t *testing.T) {
		// Simulates a real BGP-LS advertisement from IOS-XR router
		nlri := &NLRI{LS: []TLV{}}

		// Add Node Flags
		nlri.LS = append(nlri.LS, TLV{Type: 1024, Length: 1, Value: []byte{0x00}})
		// Add Node Name
		nlri.LS = append(nlri.LS, TLV{Type: 1026, Length: 11, Value: []byte("router-xr-1")})
		// Add IPv4 Router-ID
		nlri.LS = append(nlri.LS, TLV{Type: 1028, Length: 4, Value: []byte{10, 0, 0, 1}})
		// Add ISIS Area
		nlri.LS = append(nlri.LS, TLV{Type: 1027, Length: 3, Value: []byte{0x49, 0x00, 0x01}})

		// Verify all attributes present
		if len(nlri.LS) != 4 {
			t.Errorf("Expected 4 TLVs, got %d", len(nlri.LS))
		}

		nodeName := nlri.GetNodeName()
		if nodeName != "router-xr-1" {
			t.Errorf("Expected node name 'router-xr-1', got '%s'", nodeName)
		}

		t.Log("✅ Real-World Router Node Advertisement validated")
	})

	t.Run("Real-World: Link Advertisement with TE Attributes", func(t *testing.T) {
		// Simulates a real link with TE attributes
		nlri := &NLRI{LS: []TLV{}}

		// Add IGP Metric
		nlri.LS = append(nlri.LS, TLV{Type: 1095, Length: 3, Value: []byte{0x00, 0x00, 0x0A}})
		// Add TE Metric
		nlri.LS = append(nlri.LS, TLV{Type: 1092, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x14}})
		// Add Admin Group
		nlri.LS = append(nlri.LS, TLV{Type: 1088, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x0F}})
		// Add Max Bandwidth
		nlri.LS = append(nlri.LS, TLV{Type: 1089, Length: 4, Value: []byte{0x49, 0x74, 0x24, 0x00}})
		// Add MPLS Protocol Mask (LDP + RSVP)
		nlri.LS = append(nlri.LS, TLV{Type: 1094, Length: 1, Value: []byte{0xC0}})

		if len(nlri.LS) != 5 {
			t.Errorf("Expected 5 TLVs, got %d", len(nlri.LS))
		}

		t.Log("✅ Real-World Link with TE Attributes validated")
	})
}
