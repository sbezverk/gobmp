package unicast

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func TestUnmarshalUnicastNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *MPUnicastNLRI
	}{
		// {
		// 	name:  "mp unicast nlri 1",
		// 	input: []byte{0x18, 0x0a, 0x00, 0x82},
		// 	expect: &MPUnicastNLRI{
		// 		NLRI: []MPUnicastPrefix{
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  0,
		// 				Length: 0x18,
		// 				Prefix: []byte{0x0a, 0x00, 0x82},
		// 			},
		// 		},
		// 	},
		// },
		// {
		// 	name:  "mp unicast nlri 2",
		// 	input: []byte{0x00, 0x00, 0x00, 0x01, 0x20, 0x0a, 0x00, 0x00, 0x02},
		// 	expect: &MPUnicastNLRI{
		// 		NLRI: []MPUnicastPrefix{
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x20,
		// 				Prefix: []byte{0x0a, 0x00, 0x00, 0x02},
		// 			},
		// 		},
		// 	},
		// },
		// {
		// 	name:  "mp unicast nlri 3",
		// 	input: []byte{0x00, 0x00, 0x00, 0x01, 0x16, 0x47, 0x47, 0x08, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x04, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x03, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x02, 0x00, 0x00, 0x00, 0x01, 0x18, 0x47, 0x47, 0x01},
		// 	expect: &MPUnicastNLRI{
		// 		NLRI: []MPUnicastPrefix{
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x16,
		// 				Prefix: []byte{0x47, 0x47, 0x08},
		// 			},
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x18,
		// 				Prefix: []byte{0x47, 0x47, 0x04},
		// 			},
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x18,
		// 				Prefix: []byte{0x47, 0x47, 0x03},
		// 			},
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x18,
		// 				Prefix: []byte{0x47, 0x47, 0x02},
		// 			},
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  1,
		// 				Length: 0x18,
		// 				Prefix: []byte{0x47, 0x47, 0x01},
		// 			},
		// 		},
		// 	},
		// },
		// {
		// 	name:  "Default prefix",
		// 	input: []byte{0x0},
		// 	expect: &MPUnicastNLRI{
		// 		NLRI: []MPUnicastPrefix{
		// 			{
		// 				AFI:    0,
		// 				SAFI:   0,
		// 				Count:  0,
		// 				Length: 0x0,
		// 				Prefix: []byte{},
		// 			},
		// 		},
		// 	},
		// },
		{
			name:  "Panic case #1",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x17, 0x89, 0xe8, 0x70},
			expect: &MPUnicastNLRI{
				NLRI: []MPUnicastPrefix{
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 23,
						Prefix: []byte{137, 232, 112},
					},
				},
			},
		},
		{
			name:  "Panic case #2",
			input: []byte{0x00, 0x00, 0x00, 0x01, 0x17, 0xd8, 0xee, 0xfe, 0x00, 0x00, 0x00, 0x01, 0x18, 0xcd, 0x6b, 0x58, 0x00, 0x00, 0x00, 0x01, 0x14, 0xcd, 0x63, 0x40, 0x00, 0x00, 0x00, 0x01, 0x18, 0xb1, 0xc8, 0xef, 0x00, 0x00, 0x00, 0x01, 0x18, 0xb1, 0xc8, 0xee},
			expect: &MPUnicastNLRI{
				NLRI: []MPUnicastPrefix{
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 23,
						Prefix: []byte{216, 238, 254},
					},
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 24,
						Prefix: []byte{205, 107, 88},
					},
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 20,
						Prefix: []byte{205, 99, 64},
					},
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 24,
						Prefix: []byte{177, 200, 239},
					},
					{
						AFI:    0,
						SAFI:   0,
						Count:  1,
						Length: 24,
						Prefix: []byte{177, 200, 238},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalUnicastNLRI(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}

func TestUnmarshalLUNLRI(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *MPUnicastNLRI
	}{
		{
			name:  "mp unicast nlri 1",
			input: []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x00, 0x00, 0x00},
			expect: &MPUnicastNLRI{
				NLRI: []MPUnicastPrefix{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x00},
					},
				},
			},
		},
		{
			name:  "mp unicast nlri 1",
			input: []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x00, 0x00, 0x00},
			expect: &MPUnicastNLRI{
				NLRI: []MPUnicastPrefix{
					{
						Length: 32,
						Label: []*base.Label{
							{
								Value: 3,
								Exp:   0x0,
								BoS:   true,
							},
						},
						Prefix: []byte{0x0a, 0x00, 0x00, 0x00},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalLUNLRI(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}
