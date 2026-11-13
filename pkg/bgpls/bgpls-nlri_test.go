package bgpls

import (
	"testing"
)

func TestGetLSSourceRouterID_OSPF(t *testing.T) {
	tests := []struct {
		name    string
		tlvs    []TLV
		want    string
		wantErr string
	}{
		{
			name: "TLV 1174 OSPF Router-ID",
			tlvs: []TLV{
				{
					Type:   1174,
					Length: 4,
					Value:  []byte{192, 0, 2, 1}, // 192.0.2.1
				},
			},
			want: "192.0.2.1",
		},
		{
			name: "TLV 1174 invalid length",
			tlvs: []TLV{
				{
					Type:   1174,
					Length: 2,
					Value:  []byte{192, 0}, // Too short
				},
			},
			want:    "",
			wantErr: "invalid length 2 for OSPF Router-ID TLV 1174, expected 4",
		},
		{
			name: "TLV 1171 fallback IPv4",
			tlvs: []TLV{
				{
					Type:   1171,
					Length: 4,
					Value:  []byte{10, 0, 0, 1}, // 10.0.0.1
				},
			},
			want: "10.0.0.1",
		},
		{
			name: "TLV 1174 takes precedence over 1171",
			tlvs: []TLV{
				{
					Type:   1171,
					Length: 4,
					Value:  []byte{10, 0, 0, 1},
				},
				{
					Type:   1174,
					Length: 4,
					Value:  []byte{192, 0, 2, 1},
				},
			},
			want: "192.0.2.1", // Should return 1174
		},
		{
			name:    "No Router-ID TLV",
			tlvs:    []TLV{},
			want:    "",
			wantErr: "source Router ID TLV 1171 not found",
		},
		{
			name: "TLV 1174 invalid length blocks 1171 fallback",
			tlvs: []TLV{
				{Type: 1171, Length: 4, Value: []byte{10, 0, 0, 1}},
				{Type: 1174, Length: 16, Value: make([]byte, 16)},
			},
			wantErr: "invalid length 16 for OSPF Router-ID TLV 1174, expected 4",
		},
		{
			name:    "TLV 1171 invalid length",
			tlvs:    []TLV{{Type: 1171, Length: 2, Value: []byte{192, 0}}},
			wantErr: "invalid length 2 of Source Router ID TLV 1171",
		},
		{
			name: "TLV 1171 IPv6",
			tlvs: []TLV{
				{
					Type:   1171,
					Length: 16,
					Value:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				},
			},
			want: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nlri := &NLRI{LS: tt.tlvs}
			got, err := nlri.GetLSSourceRouterID()
			var gotErr string
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Errorf("GetLSSourceRouterID() error = %q, want %q", gotErr, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("GetLSSourceRouterID() = %v, want %v", got, tt.want)
			}
		})
	}
}
