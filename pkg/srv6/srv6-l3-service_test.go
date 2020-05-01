package srv6

import (
	"reflect"
	"testing"
)

func TestUnmarshalSRv6L3Service(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *L3Service
	}{
		{
			name:  "SRv6 L3 Service 1",
			input: []byte{0x00, 0x01, 0x00, 0x1e, 0x00, 0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40},
			expect: &L3Service{
				ServiceSubTLV: map[uint8]*ServiceSubTLV{
					1: &ServiceSubTLV{
						Type:   1,
						Length: 30,
						Value: &InformationSubTLV{
							SID:              []byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
							Flags:            0,
							EndpointBehavior: 19,
							SubSubTLV: map[uint8]*ServiceSubTLV{
								1: &ServiceSubTLV{
									Type:   1,
									Length: 6,
									Value: &SIDStructureSubSubTLV{
										LocalBlockLength:    0x28,
										LocatorNodeLength:   0x18,
										FunctionLength:      0x10,
										ArgumentLength:      0,
										TranspositionLength: 0x10,
										TranspositionOffset: 0x40,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRv6L3Service(tt.input)
			if err != nil {
				t.Fatalf("test failed with error: %+v", err)
			}
			//			fmt.Printf("got: \n%+v\n expect:\n%+v\n", got.ServiceSubTLV[1], tt.expect.ServiceSubTLV[1])
			//			fmt.Printf("got: \n%+v\n expect:\n%+v\n", got.ServiceSubTLV[1].Value.(*InformationSubTLV), tt.expect.ServiceSubTLV[1].Value.(*InformationSubTLV))
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}

		})
	}
}
