package main

import (
	"flag"
	"reflect"
	"testing"
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
		expect *BMPCommonHeader
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{3, 0, 0, 0, 32, 4},
			expect: &BMPCommonHeader{
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
			message, err := UnmarshalCommonHeader(tt.input)
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
		expect *BMPInitiationMessage
		fail   bool
	}{
		{
			name:  "valid 2 TLVs",
			input: []byte{0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: &BMPInitiationMessage{
				TLV: []InformationalTLV{
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
			message, err := UnmarshalInitiationMessage(tt.input)
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
		expect *BGPOpenMessage
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2},
			expect: &BGPOpenMessage{
				Length:  91,
				Type:    1,
				Version: 4,
				MyAS:    5070, HoldTime: 90,
				BGPID:       []byte{192, 168, 8, 8},
				OptParamLen: 62,
				OptionalParameters: []BGPInformationalTLV{
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
			message, err := UnmarshalBGPOpenMessage(tt.input)
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

// Stats Report 0 0 0 3 0 1 0 4 0 0 1 164 0 7 0 8 0 0 0 0 0 0 0 21 0 8 0 8 0 0 0 0 0 0 0 21
// {StatsCount:3 StatsTLV:[{InformationType:1 InformationLength:4 Information:[0 0 1 164]} {InformationType:7 InformationLength:8 Information:[0 0 0 0 0 0 0 21]} {InformationType:8 InformationLength:8 Information:[0 0 0 0 0 0 0 21]}]}
func TestParsingWorker(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "test 1",
			input: []byte{3, 0, 0, 0, 32, 4, 0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49, 3, 0, 0, 0, 234, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 103, 0, 0, 19, 206, 57, 112, 1, 254, 94, 98, 129, 171, 0, 0, 215, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 128, 0, 179, 131, 152, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 75, 1, 4, 19, 206, 0, 90, 57, 112, 1, 254, 46, 2, 44, 2, 0, 1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1, 1, 4, 0, 1, 0, 4, 1, 4, 0, 2, 0, 4, 1, 4, 0, 1, 0, 128, 1, 4, 0, 2, 0, 128, 65, 4, 0, 0, 19, 206},
		},
		//		{
		//			name:  "test 2",
		//			input: []byte{3, 0, 0, 0, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 8, 8, 0, 0, 19, 206, 192, 168, 8, 8, 94, 102, 174, 209, 0, 3, 125, 214, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 79, 2, 0, 0, 0, 56, 144, 14, 0, 18, 0, 1, 1, 4, 192, 168, 8, 8, 0, 0, 0, 0, 1, 32, 192, 168, 8, 8, 64, 1, 1, 0, 64, 2, 0, 128, 4, 4, 0, 0, 0, 0, 64, 5, 4, 0, 0, 0, 100, 192, 40, 10, 1, 0, 7, 0, 0, 0, 0, 0, 0, 1, 3, 0, 0, 0, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 8, 8, 0, 0, 19, 206, 192, 168, 8, 8, 94, 102, 174, 209, 0, 3, 125, 234, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 74, 2, 0, 0, 0, 51, 144, 14, 0, 26, 0, 1, 1, 4, 192, 168, 8, 8, 0, 0, 0, 0, 1, 24, 192, 168, 80, 0, 0, 0, 1, 30, 10, 0, 0, 0, 64, 1, 1, 2, 64, 2, 0, 128, 4, 4, 0, 0, 0, 0, 64, 5, 4, 0, 0, 0, 100, 3, 0, 0, 0, 138, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 8, 8, 0, 0, 19, 206, 192, 168, 8, 8, 94, 102, 174, 209, 0, 3, 127, 13},
		//		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsingWorker(tt.input)
		})
	}
}
