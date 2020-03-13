package main

import (
	"flag"
	"fmt"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsingWorker(tt.input)
		})
	}
}

func TestUnmarshalBMPRouteMonitorMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *BMPRouteMonitor
		fail   bool
	}{
		{
			name:  "update 1",
			input: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x08, 0x08, 0x00, 0x00, 0x13, 0xce, 0xc0, 0xa8, 0x08, 0x08, 0x5e, 0x68, 0x0a, 0xe9, 0x00, 0x0b, 0x90, 0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x4f, 0x02, 0x00, 0x00, 0x00, 0x38, 0x90, 0x0e, 0x00, 0x12, 0x00, 0x01, 0x01, 0x04, 0xc0, 0xa8, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0xc0, 0xa8, 0x08, 0x08, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0xc0, 0x28, 0x0a, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expect: &BMPRouteMonitor{
				Updates: []BGPUpdate{
					{
						WithdrawnRoutesLength: 0,
						WithdrawnRoutes: BGPWithdrawnRoutes{
							WithdrawnRoutes: nil,
						},
						TotalPathAttributeLength: 56,
						PathAttributes: []BGPPathAttribute{
							{
								AttributeTypeFlags: 144,
								AttributeType:      14,
								AttributeLength:    18,
								Attribute:          []byte{0, 1, 1, 4, 192, 168, 8, 8, 0, 0, 0, 0, 1, 32, 192, 168, 8, 8},
							},
							{
								AttributeTypeFlags: 64,
								AttributeType:      1,
								AttributeLength:    1,
								Attribute:          []byte{0},
							},
							{
								AttributeTypeFlags: 64,
								AttributeType:      2,
								AttributeLength:    0,
								Attribute:          []byte{},
							},
							{
								AttributeTypeFlags: 128,
								AttributeType:      4,
								AttributeLength:    4,
								Attribute:          []byte{0, 0, 0, 0},
							},
							{
								AttributeTypeFlags: 64,
								AttributeType:      5,
								AttributeLength:    4,
								Attribute:          []byte{0, 0, 0, 100},
							},
							{
								AttributeTypeFlags: 192,
								AttributeType:      40,
								AttributeLength:    10,
								Attribute:          []byte{1, 0, 7, 0, 0, 0, 0, 0, 0, 1},
							},
						},
						NLRI: []byte{},
					},
				},
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ru, err := UnmarshalBMPRouteMonitorMessage(tt.input)
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
			fmt.Printf("%+v\n", ru)
			if !reflect.DeepEqual(ru, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}

// {0x03, 0x00, 0x00, 0x01, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x08, 0x08, 0x00, 0x00, 0x13, 0xce, 0xc0, 0xa8, 0x08, 0x08, 0x5e, 0x6a, 0xc6, 0xee, 0x00, 0x0b, 0xb4, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x35, 0x02, 0x00, 0x00, 0x01, 0x1e, 0x90, 0x0e, 0x00, 0x62, 0x40, 0x04, 0x47, 0x04, 0xc0, 0xa8, 0x08, 0x08, 0x00, 0x00, 0x02, 0x00, 0x55, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x01, 0x01, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x03, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x04, 0x0a, 0x00, 0x00, 0x02, 0x40, 0x01, 0x01, 0x00, 0x40, 0x02, 0x00, 0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64, 0x80, 0x1d, 0xa7, 0x01, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x0b, 0x00, 0x02, 0x01, 0x0a, 0x04, 0x04, 0x00, 0x04, 0xc0, 0xa8, 0x09, 0x09, 0x04, 0x06, 0x00, 0x04, 0xc0, 0xa8, 0x08, 0x08, 0x04, 0x40, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x41, 0x00, 0x04, 0x4c, 0xee, 0x6b, 0x28, 0x04, 0x42, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x04, 0x43, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x44, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x04, 0x47, 0x00, 0x03, 0x00, 0x00, 0x01, 0x04, 0x4b, 0x00, 0x07, 0x70, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xc0, 0x04, 0x4b, 0x00, 0x07, 0x30, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xc1, 0x04, 0x95, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
