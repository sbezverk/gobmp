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

func TestLinkBandwidthTransitive(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name: "transitive link-bw 1000 bytes/sec AS 65000",
			// Type=0x00, SubType=0x04, GA=0xFDE8 (AS 65000), LA=0x447A0000 (1000.0 float32)
			input:  []byte{0x00, 0x04, 0xFD, 0xE8, 0x44, 0x7A, 0x00, 0x00},
			expect: "link-bw=1000.000000",
		},
		{
			name: "transitive link-bw 0 bytes/sec AS 100",
			// Type=0x00, SubType=0x04, GA=0x0064 (AS 100), LA=0x00000000 (0.0 float32)
			input:  []byte{0x00, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00},
			expect: "link-bw=0.000000",
		},
		{
			name: "transitive link-bw 1 byte/sec AS 23456 (AS_TRANS)",
			// Type=0x00, SubType=0x04, GA=0x5BA0 (AS_TRANS 23456), LA=0x3F800000 (1.0 float32)
			input:  []byte{0x00, 0x04, 0x5B, 0xA0, 0x3F, 0x80, 0x00, 0x00},
			expect: "link-bw=1.000000",
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

func TestLinkBandwidthNonTransitive(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name: "non-transitive link-bw 1000 bytes/sec AS 65000",
			// Type=0x40, SubType=0x04, GA=0xFDE8 (AS 65000), LA=0x447A0000 (1000.0 float32)
			input:  []byte{0x40, 0x04, 0xFD, 0xE8, 0x44, 0x7A, 0x00, 0x00},
			expect: "link-bw=1000.000000",
		},
		{
			name: "non-transitive link-bw 0 bytes/sec AS 100",
			// Type=0x40, SubType=0x04, GA=0x0064 (AS 100), LA=0x00000000 (0.0 float32)
			input:  []byte{0x40, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00},
			expect: "link-bw=0.000000",
		},
		{
			name: "non-transitive link-bw 1 byte/sec AS 23456",
			// Type=0x40, SubType=0x04, GA=0x5BA0 (AS 23456), LA=0x3F800000 (1.0 float32)
			input:  []byte{0x40, 0x04, 0x5B, 0xA0, 0x3F, 0x80, 0x00, 0x00},
			expect: "link-bw=1.000000",
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
