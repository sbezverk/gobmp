package base

import (
	"reflect"
	"testing"
)

func TestProtocolIDString(t *testing.T) {
	cases := []struct {
		id   ProtoID
		want string
	}{
		{ISISL1, "IS-IS Level 1"},
		{ISISL2, "IS-IS Level 2"},
		{OSPFv2, "OSPFv2"},
		{Direct, "Direct"},
		{Static, "Static configuration"},
		{OSPFv3, "OSPFv3"},
		{BGP, "BGP"},
		{RSVPTE, "RSVP-TE"},
		{SR, "Segment Routing"},
		{255, "Unknown"},
	}
	for _, c := range cases {
		if got := ProtocolIDString(c.id); got != c.want {
			t.Errorf("ProtocolIDString(%d) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestPrefixNLRIAccessors(t *testing.T) {
	p := &PrefixNLRI{
		ProtocolID: BGP, // 7
		Identifier: [8]byte{0, 0, 0, 0, 0, 0, 0, 99},
		LocalNode: &NodeDescriptor{
			SubTLV: map[uint16]TLV{
				512: {Type: 512, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x0a}}, // ASN=10
				513: {Type: 513, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x02}}, // LSID=2
				514: {Type: 514, Length: 4, Value: []byte{0x00, 0x00, 0x00, 0x04}}, // OSPF=4
				515: {Type: 515, Length: 4, Value: []byte{10, 0, 0, 1}},            // IGP=10.0.0.1
			},
		},
	}

	if got := p.GetPrefixProtocolID(); got != "BGP" {
		t.Errorf("GetPrefixProtocolID() = %q, want \"BGP\"", got)
	}
	if got := p.GetIdentifier(); got != 99 {
		t.Errorf("GetIdentifier() = %d, want 99", got)
	}
	if got := p.GetPrefixASN(); got != 10 {
		t.Errorf("GetPrefixASN() = %d, want 10", got)
	}
	if got := p.GetPrefixLSID(); got != 2 {
		t.Errorf("GetPrefixLSID() = %d, want 2", got)
	}
	if got := p.GetPrefixOSPFAreaID(); got != "4" {
		t.Errorf("GetPrefixOSPFAreaID() = %q, want \"4\"", got)
	}
	if got := p.GetLocalIGPRouterID(); got != "10.0.0.1" {
		t.Errorf("GetLocalIGPRouterID() = %q, want \"10.0.0.1\"", got)
	}
	if got := p.GetLocalASN(); got != 10 {
		t.Errorf("GetLocalASN() = %d, want 10", got)
	}
}

func TestUnmarshalPrefixNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		expect  *PrefixNLRI
		ipv4    bool
		wantErr bool
	}{
		{
			name:    "prefix nlri empty",
			input:   []byte{},
			expect:  nil,
			wantErr: true,
		},
		{
			name:    "prefix nlri malformed",
			input:   []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect:  nil,
			wantErr: true,
		},
		{
			name:  "prefix nlri 1",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x07, 0x00, 0x02, 0x00, 0x02, 0x01, 0x09, 0x00, 0x10, 0x78, 0x00, 0x90, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: &PrefixNLRI{
				ProtocolID: 2,
				Identifier: [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Prefix: &PrefixDescriptor{
					PrefixTLV: map[uint16]TLV{
						263: {
							Type:   263,
							Length: 2,
							Value:  []byte{0, 2},
						},
						265: {
							Type:   265,
							Length: 16,
							Value:  []byte{120, 0, 144, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
						},
					},
				},
				LocalNodeHash: "6ba91f7f4f4032d0b82caa898b9fef8d",
				IsIPv4:        false,
			},
			ipv4: false,
		},
		{
			name:  "prefix nlri 2",
			input: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93, 0x01, 0x09, 0x00, 0x04, 0x18, 0x09, 0x00, 0xcb},
			expect: &PrefixNLRI{
				ProtocolID: 2,
				Identifier: [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				LocalNode: &NodeDescriptor{
					SubTLV: map[uint16]TLV{
						512: {
							Type:   512,
							Length: 4,
							Value:  []byte{0, 0, 19, 206},
						},
						513: {
							Type:   513,
							Length: 4,
							Value:  []byte{0, 0, 0, 0},
						},
						515: {
							Type:   515,
							Length: 6,
							Value:  []byte{0, 0, 0, 0, 0, 147},
						},
					},
				},
				Prefix: &PrefixDescriptor{
					PrefixTLV: map[uint16]TLV{
						265: {
							Type:   265,
							Length: 4,
							Value:  []byte{24, 9, 0, 203},
						},
					},
				},
				LocalNodeHash: "6ba91f7f4f4032d0b82caa898b9fef8d",
				IsIPv4:        true,
			},
			ipv4: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalPrefixNLRI(tt.input, tt.ipv4)
			if err != nil && !tt.wantErr {
				t.Fatalf("test failed with error: %+v", err)
			}
			if err == nil && tt.wantErr {
				t.Fatalf("test failed as expected error did not occur")
			}
			//			fmt.Printf("got: \n%+v\n expect:\n%+v\n", *got, *tt.expect)
			//			fmt.Printf("got local: \n%+v\n expect local:\n%+v\n", *got.LocalNode, *tt.expect.LocalNode)
			//			fmt.Printf("got prefix: \n%+v\n expect prefix:\n%+v\n", *got.Prefix, *tt.expect.Prefix)
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
