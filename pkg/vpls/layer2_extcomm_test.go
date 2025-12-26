package vpls

import (
	"testing"
)

func TestParseLayer2InfoExtComm(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		verify  func(*testing.T, *Layer2InfoExtComm)
	}{
		{
			name: "Valid Layer2 Info - Ethernet with Control Word",
			// Type: 0x800a (handled by caller)
			// Encap: Ethernet (4)
			// Flags: C=1, S=0 (0x01)
			// MTU: 1500 (0x05dc)
			// Reserved: 0x0000
			input: []byte{
				0x80, 0x0a, // Type
				0x04,       // Encap: Ethernet
				0x01,       // Flags: C=1
				0x05, 0xdc, // MTU: 1500
				0x00, 0x00, // Reserved
			},
			wantErr: false,
			verify: func(t *testing.T, ec *Layer2InfoExtComm) {
				if ec.EncapType != EncapEthernet {
					t.Errorf("EncapType = %d, want %d (Ethernet)", ec.EncapType, EncapEthernet)
				}
				if !ec.ControlWord {
					t.Error("ControlWord = false, want true")
				}
				if ec.SequencedDel {
					t.Error("SequencedDel = true, want false")
				}
				if ec.MTU != 1500 {
					t.Errorf("MTU = %d, want 1500", ec.MTU)
				}
			},
		},
		{
			name: "Valid Layer2 Info - VLAN with both flags",
			input: []byte{
				0x80, 0x0a,
				0x05,       // Encap: VLAN
				0x03,       // Flags: C=1, S=1
				0x05, 0xdc, // MTU: 1500
				0x00, 0x00,
			},
			wantErr: false,
			verify: func(t *testing.T, ec *Layer2InfoExtComm) {
				if ec.EncapType != EncapVLAN {
					t.Errorf("EncapType = %d, want %d (VLAN)", ec.EncapType, EncapVLAN)
				}
				if !ec.ControlWord {
					t.Error("ControlWord = false, want true")
				}
				if !ec.SequencedDel {
					t.Error("SequencedDel = false, want true")
				}
			},
		},
		{
			name: "Valid Layer2 Info - Ethernet VLAN (type 19)",
			input: []byte{
				0x80, 0x0a,
				0x13,       // Encap: 19 (Ethernet VLAN)
				0x00,       // Flags: none
				0x05, 0xdc, // MTU: 1500
				0x00, 0x00,
			},
			wantErr: false,
			verify: func(t *testing.T, ec *Layer2InfoExtComm) {
				if ec.EncapType != EncapEthernetVLAN {
					t.Errorf("EncapType = %d, want %d (Ethernet VLAN)", ec.EncapType, EncapEthernetVLAN)
				}
				if ec.ControlWord {
					t.Error("ControlWord = true, want false")
				}
				if ec.SequencedDel {
					t.Error("SequencedDel = true, want false")
				}
			},
		},
		{
			name: "Valid Layer2 Info - ATM AAL5",
			input: []byte{
				0x80, 0x0a,
				0x02,       // Encap: ATM AAL5
				0x00,       // Flags: none
				0x05, 0xdc, // MTU: 1500
				0x00, 0x00,
			},
			wantErr: false,
			verify: func(t *testing.T, ec *Layer2InfoExtComm) {
				if ec.EncapType != EncapATMAAL5 {
					t.Errorf("EncapType = %d, want %d (ATM AAL5)", ec.EncapType, EncapATMAAL5)
				}
			},
		},
		{
			name: "Valid Layer2 Info - Large MTU",
			input: []byte{
				0x80, 0x0a,
				0x04,       // Encap: Ethernet
				0x00,       // Flags: none
				0x23, 0x28, // MTU: 9000
				0x00, 0x00,
			},
			wantErr: false,
			verify: func(t *testing.T, ec *Layer2InfoExtComm) {
				if ec.MTU != 9000 {
					t.Errorf("MTU = %d, want 9000", ec.MTU)
				}
			},
		},
		{
			name: "Invalid - non-zero reserved field",
			input: []byte{
				0x80, 0x0a,
				0x04,
				0x01,
				0x05, 0xdc,
				0x00, 0x01, // Reserved != 0
			},
			wantErr: true,
		},
		{
			name:    "Invalid - too short",
			input:   []byte{0x80, 0x0a, 0x04, 0x01},
			wantErr: true,
		},
		{
			name: "Invalid - too long",
			input: []byte{
				0x80, 0x0a, 0x04, 0x01,
				0x05, 0xdc, 0x00, 0x00, 0x00, // Extra byte
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ec, err := ParseLayer2InfoExtComm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLayer2InfoExtComm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.verify != nil {
				tt.verify(t, ec)
			}
		})
	}
}

func TestEncapTypeToString(t *testing.T) {
	tests := []struct {
		encapType uint8
		want      string
	}{
		{EncapFrameRelayDLCI, "Frame Relay DLCI"},
		{EncapATMAAL5, "ATM AAL5 VCC transport"},
		{EncapATMTransparent, "ATM transparent cell transport"},
		{EncapEthernet, "Ethernet (802.3)"},
		{EncapVLAN, "VLAN (802.1Q)"},
		{EncapHDLC, "HDLC"},
		{EncapPPP, "PPP"},
		{EncapSONETSDH, "SONET/SDH Circuit Emulation Service"},
		{EncapATMnto1VCC, "ATM n-to-one VCC cell transport"},
		{EncapATMnto1VPC, "ATM n-to-one VPC cell transport"},
		{EncapIPLayer2, "IP Layer 2 Transport"},
		{EncapEthernetVLAN, "Ethernet VLAN (802.1Q)"},
		{99, "Unknown (99)"}, // Unknown type
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := EncapTypeToString(tt.encapType)
			if got != tt.want {
				t.Errorf("EncapTypeToString(%d) = %s, want %s", tt.encapType, got, tt.want)
			}
		})
	}
}

func TestLayer2InfoExtComm_String(t *testing.T) {
	tests := []struct {
		name string
		ec   *Layer2InfoExtComm
		want string
	}{
		{
			name: "Ethernet with C flag",
			ec: &Layer2InfoExtComm{
				EncapType:    EncapEthernet,
				ControlWord:  true,
				SequencedDel: false,
				MTU:          1500,
			},
			want: "L2-Info: Encap=Ethernet (802.3), Flags=C, MTU=1500",
		},
		{
			name: "VLAN with both flags",
			ec: &Layer2InfoExtComm{
				EncapType:    EncapVLAN,
				ControlWord:  true,
				SequencedDel: true,
				MTU:          1500,
			},
			want: "L2-Info: Encap=VLAN (802.1Q), Flags=C,S, MTU=1500",
		},
		{
			name: "Ethernet with no flags",
			ec: &Layer2InfoExtComm{
				EncapType:    EncapEthernet,
				ControlWord:  false,
				SequencedDel: false,
				MTU:          9000,
			},
			want: "L2-Info: Encap=Ethernet (802.3), Flags=none, MTU=9000",
		},
		{
			name: "ATM AAL5 with S flag only",
			ec: &Layer2InfoExtComm{
				EncapType:    EncapATMAAL5,
				ControlWord:  false,
				SequencedDel: true,
				MTU:          1500,
			},
			want: "L2-Info: Encap=ATM AAL5 VCC transport, Flags=S, MTU=1500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ec.String()
			if got != tt.want {
				t.Errorf("String() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestParseRouteTarget tests Route Target Extended Community parsing (RFC 4360)
func TestParseRouteTarget(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *RouteTarget
		wantStr string
		wantErr bool
	}{
		{
			name: "Type 0x0002 - 2-octet AS Specific",
			input: []byte{
				0x00, 0x02, // Type: 2-octet AS Specific
				0xfd, 0xe8, // AS: 65000
				0x00, 0x00, 0x00, 0x64, // Assigned: 100
			},
			want: &RouteTarget{
				Type:        0x0002,
				AS:          65000,
				AssignedNum: 100,
			},
			wantStr: "RT:65000:100",
			wantErr: false,
		},
		{
			name: "Type 0x0102 - IPv4 Address Specific",
			input: []byte{
				0x01, 0x02, // Type: IPv4 Address Specific
				10, 0, 0, 1, // IPv4: 10.0.0.1
				0x00, 0x64, // Assigned: 100
			},
			want: &RouteTarget{
				Type:        0x0102,
				IPv4:        "10.0.0.1",
				AssignedNum: 100,
			},
			wantStr: "RT:10.0.0.1:100",
			wantErr: false,
		},
		{
			name: "Type 0x0202 - 4-octet AS Specific",
			input: []byte{
				0x02, 0x02, // Type: 4-octet AS Specific
				0x00, 0x01, 0x00, 0x00, // AS: 65536
				0x00, 0xc8, // Assigned: 200
			},
			want: &RouteTarget{
				Type:        0x0202,
				AS:          65536,
				AssignedNum: 200,
			},
			wantStr: "RT:65536:200",
			wantErr: false,
		},
		{
			name: "Invalid length - too short",
			input: []byte{
				0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x64, // 7 bytes
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid length - too long",
			input: []byte{
				0x00, 0x02, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x64, 0xff, // 9 bytes
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Unknown RT type",
			input: []byte{
				0x99, 0x99, // Unknown type
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRouteTarget(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRouteTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Check Type
			if got.Type != tt.want.Type {
				t.Errorf("Type = 0x%04x, want 0x%04x", got.Type, tt.want.Type)
			}

			// Check fields based on type
			switch tt.want.Type {
			case 0x0002, 0x0202:
				if got.AS != tt.want.AS {
					t.Errorf("AS = %d, want %d", got.AS, tt.want.AS)
				}
			case 0x0102:
				if got.IPv4 != tt.want.IPv4 {
					t.Errorf("IPv4 = %s, want %s", got.IPv4, tt.want.IPv4)
				}
			}

			if got.AssignedNum != tt.want.AssignedNum {
				t.Errorf("AssignedNum = %d, want %d", got.AssignedNum, tt.want.AssignedNum)
			}

			// Check String() output
			if gotStr := got.String(); gotStr != tt.wantStr {
				t.Errorf("String() = %s, want %s", gotStr, tt.wantStr)
			}
		})
	}
}

// TestRouteTarget_String tests RouteTarget String() method edge cases
func TestRouteTarget_String(t *testing.T) {
	tests := []struct {
		name string
		rt   *RouteTarget
		want string
	}{
		{
			name: "2-octet AS with small values",
			rt: &RouteTarget{
				Type:        0x0002,
				AS:          100,
				AssignedNum: 1,
			},
			want: "RT:100:1",
		},
		{
			name: "4-octet AS with large values",
			rt: &RouteTarget{
				Type:        0x0202,
				AS:          4294967295, // Max uint32
				AssignedNum: 65535,      // Max uint16
			},
			want: "RT:4294967295:65535",
		},
		{
			name: "IPv4 with max assigned number",
			rt: &RouteTarget{
				Type:        0x0102,
				IPv4:        "192.168.1.1",
				AssignedNum: 65535,
			},
			want: "RT:192.168.1.1:65535",
		},
		{
			name: "Unknown type",
			rt: &RouteTarget{
				Type: 0xFFFF,
			},
			want: "RT:unknown-type-0xffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rt.String()
			if got != tt.want {
				t.Errorf("String() = %s, want %s", got, tt.want)
			}
		})
	}
}
