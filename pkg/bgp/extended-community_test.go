package bgp

import (
	"testing"
)

func TestFlowspecTrafficAction(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "terminal action set, sample clear",
			input:  []byte{0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expect: "flowspec-traffic-action=T=true S=false",
		},
		{
			name:   "terminal action clear, sample set",
			input:  []byte{0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			expect: "flowspec-traffic-action=T=false S=true",
		},
		{
			name:   "both bits set",
			input:  []byte{0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
			expect: "flowspec-traffic-action=T=true S=true",
		},
		{
			name:   "both bits clear",
			input:  []byte{0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: "flowspec-traffic-action=T=false S=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := makeExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("makeExtCommunity() error = %v", err)
			}
			result := ext.String()
			if result != tt.expect {
				t.Errorf("got %s, want %s", result, tt.expect)
			}
		})
	}
}

func TestFlowspecTrafficRemarking(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "DSCP 0 (default)",
			input:  []byte{0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expect: "flowspec-traffic-remarking=DSCP=0",
		},
		{
			name:   "DSCP 46 (EF - Expedited Forwarding)",
			input:  []byte{0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E},
			expect: "flowspec-traffic-remarking=DSCP=46",
		},
		{
			name:   "DSCP 26 (AF31)",
			input:  []byte{0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A},
			expect: "flowspec-traffic-remarking=DSCP=26",
		},
		{
			name:   "DSCP 63 (maximum)",
			input:  []byte{0x80, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F},
			expect: "flowspec-traffic-remarking=DSCP=63",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := makeExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("makeExtCommunity() error = %v", err)
			}
			result := ext.String()
			if result != tt.expect {
				t.Errorf("got %s, want %s", result, tt.expect)
			}
		})
	}
}

func TestLinkBandwidth(t *testing.T) {
	tests := []struct {
		name   string
		asn    uint16
		bw     []byte // 4-byte IEEE 754 float32
		expect string
	}{
		{
			name:   "1000 bytes/sec AS 65000",
			asn:    65000,
			bw:     []byte{0x44, 0x7A, 0x00, 0x00}, // 1000.0
			expect: "link-bw=1000.000000",
		},
		{
			name:   "0 bytes/sec AS 100",
			asn:    100,
			bw:     []byte{0x00, 0x00, 0x00, 0x00}, // 0.0
			expect: "link-bw=0.000000",
		},
		{
			name:   "1 byte/sec AS 23456 (AS_TRANS)",
			asn:    23456,
			bw:     []byte{0x3F, 0x80, 0x00, 0x00}, // 1.0
			expect: "link-bw=1.000000",
		},
	}

	types := []struct {
		name   string
		typeByte byte
	}{
		{"transitive", 0x00},
		{"non-transitive", 0x40},
	}

	for _, typ := range types {
		typ := typ
		for _, tt := range tests {
			tt := tt
			name := typ.name + " " + tt.name
			input := []byte{typ.typeByte, 0x04, byte(tt.asn >> 8), byte(tt.asn)}
			input = append(input, tt.bw...)
			t.Run(name, func(t *testing.T) {
				ext, err := makeExtCommunity(input)
				if err != nil {
					t.Fatalf("makeExtCommunity() error = %v", err)
				}
				result := ext.String()
				if result != tt.expect {
					t.Errorf("got %s, want %s", result, tt.expect)
				}
			})
		}
	}
}

func TestLinkBandwidthTruncatedValue(t *testing.T) {
	type0LinkBW := func(v []byte) string { return type0(0x04, v) }
	type40LinkBW := func(v []byte) string { return type40(0x04, v) }

	tests := []struct {
		name   string
		fn     func([]byte) string
		value  []byte
		expect string
	}{
		{"type0 empty value", type0LinkBW, nil, "invalid-type0-length=0"},
		{"type0 3-byte value", type0LinkBW, []byte{0xFD, 0xE8, 0x44}, "invalid-type0-length=3"},
		{"type40 empty value", type40LinkBW, nil, "invalid-type40-length=0"},
		{"type40 3-byte value", type40LinkBW, []byte{0xFD, 0xE8, 0x44}, "invalid-type40-length=3"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if result := tt.fn(tt.value); result != tt.expect {
				t.Errorf("got %s, want %s", result, tt.expect)
			}
		})
	}
}
