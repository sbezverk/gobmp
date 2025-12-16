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
