package main

import (
	"flag"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestMain(m *testing.M) {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	m.Run()
}
func TestCommonHeader(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *bmp.CommonHeader
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{3, 0, 0, 0, 32, 4},
			expect: &bmp.CommonHeader{
				Version:       3,
				MessageLength: 32,
				MessageType:   4,
			},
			fail: false,
		},
		{
			name:   "invalid version",
			input:  []byte{33, 0, 0, 0, 32, 4},
			expect: nil,
			fail:   true,
		},
		{
			name:   "invalid type 10",
			input:  []byte{3, 0, 0, 0, 32, 10},
			expect: nil,
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := bmp.UnmarshalCommonHeader(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}

func TestInitiationMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *bmp.InitiationMessage
		fail   bool
	}{
		{
			name:  "valid 2 TLVs",
			input: []byte{0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: &bmp.InitiationMessage{
				TLV: []bmp.InformationalTLV{
					{
						InformationType:   1,
						InformationLength: 10,
						Information:       []byte{32, 55, 46, 50, 46, 49, 46, 50, 51, 73},
					},
					{
						InformationType:   2,
						InformationLength: 8,
						Information:       []byte{120, 114, 118, 57, 107, 45, 114, 49},
					},
				},
			},
			fail: false,
		},
		{
			name:   "invalid 2 TLVs wrong type 3",
			input:  []byte{0, 3, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: nil,
			fail:   true,
		},
		{
			name:   "invalid 2 TLVs wrong length 100",
			input:  []byte{0, 1, 0, 100, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: nil,
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := bmp.UnmarshalInitiationMessage(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}

func TestUnmarshalBGPOpenMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *bgp.OpenMessage
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
			expect: &bgp.OpenMessage{
				Length:  91,
				Type:    1,
				Version: 4,
				MyAS:    5070, HoldTime: 90,
				BGPID:       []byte{192, 168, 8, 8},
				OptParamLen: 62,
				OptionalParameters: []bgp.InformationalTLV{
					{
						Type:   2,
						Length: 6,
						Value:  []byte{1, 4, 0, 1, 0, 1},
					},
					{
						Type:   2,
						Length: 6,
						Value:  []byte{1, 4, 0, 1, 0, 4},
					},
					{
						Type:   2,
						Length: 6,
						Value:  []byte{1, 4, 0, 1, 0, 128},
					},
					{
						Type:   2,
						Length: 2,
						Value:  []byte{128, 0},
					},
					{
						Type:   2,
						Length: 2,
						Value:  []byte{2, 0},
					},
					{
						Type:   2,
						Length: 6,
						Value:  []byte{65, 4, 0, 0, 19, 206},
					},
					{
						Type:   2,
						Length: 20,
						Value:  []byte{5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
					},
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := bgp.UnmarshalBGPOpenMessage(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}
