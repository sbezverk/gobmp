package mup

import (
	"encoding/json"
	"testing"
)

func TestTLVMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		tlv  *TLV
		want string
	}{
		{
			name: "3gpp-5g Session Parameters",
			tlv:  &TLV{Type: TLVTypeSessionParameters, Length: 5, Value: []byte{0x00, 0x00, 0x00, 0xc8, 0x09}},
			want: `{"type":1,"teid":200,"qfi":9}`,
		},
		{
			name: "3gpp-5g Session Parameters with QFI 0",
			tlv:  &TLV{Type: TLVTypeSessionParameters, Length: 5, Value: []byte{0x00, 0x00, 0x00, 0xc8, 0x00}},
			want: `{"type":1,"teid":200,"qfi":0}`,
		},
		{
			name: "Interwork Endpoint IPv4",
			tlv:  &TLV{Type: TLVTypeInterworkEndpoint, Length: 4, Value: v4("10.20.30.40")},
			want: `{"type":2,"address":"10.20.30.40"}`,
		},
		{
			name: "Source Address IPv6",
			tlv:  &TLV{Type: TLVTypeSourceAddress, Length: 16, Value: v6("2001::100")},
			want: `{"type":3,"address":"2001::100"}`,
		},
		{
			name: "unknown type keeps the raw value",
			tlv:  &TLV{Type: 200, Length: 4, Value: []byte{0xde, 0xad, 0xbe, 0xef}},
			want: `{"type":200,"value":"0xdeadbeef"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.tlv)
			if err != nil {
				t.Fatalf("json.Marshal() unexpected error: %+v", err)
			}
			if string(b) != tt.want {
				t.Fatalf("json.Marshal() = %s, want %s", b, tt.want)
			}
		})
	}
}

func TestRouteMarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		ipv6  bool
		want  string
	}{
		{
			name: "Interwork Segment Discovery",
			input: []byte{
				0x01, 0x00, 0x01, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0x0a, 0x0a, 0x0a,
			},
			want: `{"rd":"100:100","prefix":"10.10.10.0","prefix_len":24}`,
		},
		{
			name: "Direct Segment Discovery",
			input: []byte{
				0x01, 0x00, 0x02, 0x0c,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x0a, 0x0a, 0x0a, 0x01,
			},
			want: `{"rd":"100:100","address":"10.10.10.1"}`,
		},
		{
			name: "Type 1 ST with Source Address",
			input: []byte{
				0x01, 0x00, 0x03, 0x1b,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x18, 0xc0, 0x64, 0x00,
				0x00, 0x00, 0x00, 0x64,
				0x09,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
				0x20, 0x0a, 0x0a, 0x0a, 0x02,
			},
			want: `{"rd":"100:100","prefix":"192.100.0.0","prefix_len":24,"teid":100,"qfi":9,` +
				`"endpoint_address":"10.10.10.1","endpoint_len":32,"source_address":"10.10.10.2"}`,
		},
		{
			// Endpoint Length stops at the endpoint address, so the route
			// carries no TEID and none is rendered.
			name: "Type 2 ST without TEID",
			input: []byte{
				0x01, 0x00, 0x04, 0x0d,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x20, 0x0a, 0x0a, 0x0a, 0x01,
			},
			want: `{"rd":"100:100","endpoint_address":"10.10.10.1","endpoint_len":32}`,
		},
		{
			name: "Type 2 ST with Session Parameters TLV",
			input: []byte{
				0x01, 0x00, 0x04, 0x18,
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64,
				0x40, 0x0a, 0x0a, 0x0a, 0x01,
				0x00, 0x00, 0x00, 0x64,
				0x01, 0x05, 0x00, 0x00, 0x00, 0xc8, 0x09,
			},
			want: `{"rd":"100:100","endpoint_address":"10.10.10.1","endpoint_len":64,"teid":100,` +
				`"tlvs":[{"type":1,"teid":200,"qfi":9}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := UnmarshalMUPNLRI(tt.input, tt.ipv6, false)
			if err != nil {
				t.Fatalf("UnmarshalMUPNLRI() unexpected error: %+v", err)
			}
			b, err := json.Marshal(r.Route[0].GetRouteTypeSpec())
			if err != nil {
				t.Fatalf("json.Marshal() unexpected error: %+v", err)
			}
			if string(b) != tt.want {
				t.Fatalf("json.Marshal() = %s, want %s", b, tt.want)
			}
		})
	}
}
