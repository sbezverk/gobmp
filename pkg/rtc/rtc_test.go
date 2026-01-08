package rtc

import (
	"testing"
)

func TestUnmarshalRTCNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *Route
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid - Wildcard (0 bits)",
			input: []byte{
				0x00, // Length: 0 bits (wildcard)
			},
			want: &Route{
				NLRI: []*NLRI{
					{
						Length:      0,
						OriginAS:    0,
						RouteTarget: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid - Origin AS only (32 bits)",
			input: []byte{
				0x20,                   // Length: 32 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
			},
			want: &Route{
				NLRI: []*NLRI{
					{
						Length:      32,
						OriginAS:    65000,
						RouteTarget: nil,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid - Full NLRI Type 0 (AS 2-byte, 96 bits)",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x00, 0x02, // Type: 0x00 (2-byte AS), SubType: 0x02 (Route Target)
				0x00, 0x64, // AS: 100
				0x00, 0x00, 0x00, 0x01, // Value: 1
			},
			want: &Route{
				NLRI: []*NLRI{
					{
						Length:      96,
						OriginAS:    65000,
						RouteTarget: []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid - Full NLRI Type 1 (IPv4, 96 bits)",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x01, 0x02, // Type: 0x01 (IPv4), SubType: 0x02 (Route Target)
				10, 0, 0, 1, // IPv4: 10.0.0.1
				0x00, 0x64, // Value: 100
			},
			want: &Route{
				NLRI: []*NLRI{
					{
						Length:      96,
						OriginAS:    65000,
						RouteTarget: []byte{0x01, 0x02, 10, 0, 0, 1, 0x00, 0x64},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid - Full NLRI Type 2 (AS 4-byte, 96 bits)",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x02, 0x02, // Type: 0x02 (4-byte AS), SubType: 0x02 (Route Target)
				0x00, 0x01, 0x00, 0x00, // AS: 65536
				0x00, 0x0A, // Value: 10
			},
			want: &Route{
				NLRI: []*NLRI{
					{
						Length:      96,
						OriginAS:    65000,
						RouteTarget: []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid - Multiple NLRIs",
			input: []byte{
				// First NLRI - wildcard
				0x00, // Length: 0 bits
				// Second NLRI - AS only
				0x20,                   // Length: 32 bits
				0x00, 0x00, 0x00, 0x64, // Origin AS: 100
				// Third NLRI - Full
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x00, 0x02, // Type: 0x00, SubType: 0x02
				0x00, 0xC8, // AS: 200
				0x00, 0x00, 0x00, 0x05, // Value: 5
			},
			want: &Route{
				NLRI: []*NLRI{
					{Length: 0, OriginAS: 0, RouteTarget: nil},
					{Length: 32, OriginAS: 100, RouteTarget: nil},
					{
						Length:      96,
						OriginAS:    65000,
						RouteTarget: []byte{0x00, 0x02, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x05},
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "Invalid - Empty input",
			input:   []byte{},
			want:    nil,
			wantErr: true,
			errMsg:  "NLRI length is 0",
		},
		{
			name:  "Invalid - Incomplete length field",
			input: []byte{
				// No bytes (tested above)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid - Incomplete Origin AS",
			input: []byte{
				0x20,       // Length: 32 bits
				0x00, 0x00, // Only 2 bytes of Origin AS
			},
			want:    nil,
			wantErr: true,
			errMsg:  "incomplete",
		},
		{
			name: "Invalid - Incomplete Route Target",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x00, 0x02, 0x00, // Only 3 bytes of RT
			},
			want:    nil,
			wantErr: true,
			errMsg:  "incomplete",
		},
		{
			name: "Invalid - Length not 0, 32, or 96 (RFC violation)",
			input: []byte{
				0x18, // Length: 24 bits (RFC 4684 only allows 0, 32, or 96)
			},
			want:    nil,
			wantErr: true,
			errMsg:  "valid: 0, 32, or 96",
		},
		{
			name: "Invalid - Length not 0, 32, or 96",
			input: []byte{
				0x40, // Length: 64 bits (not valid per RFC 4684)
			},
			want:    nil,
			wantErr: true,
			errMsg:  "valid: 0, 32, or 96",
		},
		{
			name: "Invalid - Wrong Extended Community SubType",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x00, 0x03, // Type: 0x00, SubType: 0x03 (Route Origin, not Route Target!)
				0x00, 0x64, // AS: 100
				0x00, 0x00, 0x00, 0x01, // Value: 1
			},
			want:    nil,
			wantErr: true,
			errMsg:  "SubType 0x03",
		},
		{
			name: "Invalid - Unsupported Extended Community Type",
			input: []byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xFD, 0xE8, // Origin AS: 65000
				0x06, 0x02, // Type: 0x06 (EVPN), SubType: 0x02
				0x00, 0x64, // Data
				0x00, 0x00, 0x00, 0x01,
			},
			want:    nil,
			wantErr: true,
			errMsg:  "unsupported Route Target type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRTCNLRI(tt.input)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalRTCNLRI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If we expect an error and got one, optionally check error message
			if tt.wantErr && err != nil {
				if tt.errMsg != "" {
					if !contains(err.Error(), tt.errMsg) {
						t.Errorf("UnmarshalRTCNLRI() error message = %q, want substring %q", err.Error(), tt.errMsg)
					}
				}
				return
			}

			// Compare results
			if !compareRoutes(got, tt.want) {
				t.Errorf("UnmarshalRTCNLRI() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNLRIString(t *testing.T) {
	tests := []struct {
		name string
		nlri *NLRI
		want string
	}{
		{
			name: "Wildcard",
			nlri: &NLRI{Length: 0},
			want: "RTC{wildcard}",
		},
		{
			name: "AS only",
			nlri: &NLRI{Length: 32, OriginAS: 65000},
			want: "RTC{AS=65000}",
		},
		{
			name: "Full with Route Target Type 0",
			nlri: &NLRI{
				Length:      96,
				OriginAS:    65000,
				RouteTarget: []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01},
			},
			want: "RTC{AS=65000, RT=100:1}",
		},
		{
			name: "Full with Route Target Type 1 (IPv4)",
			nlri: &NLRI{
				Length:      96,
				OriginAS:    65000,
				RouteTarget: []byte{0x01, 0x02, 10, 0, 0, 1, 0x00, 0x64},
			},
			want: "RTC{AS=65000, RT=10.0.0.1:100}",
		},
		{
			name: "Full with Route Target Type 2 (4-byte AS)",
			nlri: &NLRI{
				Length:      96,
				OriginAS:    65000,
				RouteTarget: []byte{0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0A},
			},
			want: "RTC{AS=65000, RT=65536:10}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.nlri.String()
			if got != tt.want {
				t.Errorf("NLRI.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func compareRoutes(a, b *Route) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a.NLRI) != len(b.NLRI) {
		return false
	}
	for i := range a.NLRI {
		if !compareNLRI(a.NLRI[i], b.NLRI[i]) {
			return false
		}
	}
	return true
}

func compareNLRI(a, b *NLRI) bool {
	if a.Length != b.Length {
		return false
	}
	if a.OriginAS != b.OriginAS {
		return false
	}
	return compareByteSlice(a.RouteTarget, b.RouteTarget)
}

func compareByteSlice(a, b []byte) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
