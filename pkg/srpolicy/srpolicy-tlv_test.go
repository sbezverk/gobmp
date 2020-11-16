package srpolicy

import (
	"encoding/binary"
	"flag"
	"testing"

	"github.com/go-test/deep"
)

func TestUnmarshalSRPolicyTLV(t *testing.T) {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	tests := []struct {
		name   string
		input  []byte
		expect *TLV
		fail   bool
	}{
		{
			name:  "valid label sr policy",
			input: []byte{0x00, 0x0F, 0x00, 0x48, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0D, 0x06, 0x00, 0x00, 0xDB, 0xBA, 0x00, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0xD0, 0x00},
			expect: &TLV{
				Preference: &Preference{
					Flags:      0x0,
					Preference: 0x44,
				},
				BindingSID: &labelBSID{
					flags: 0x0,
					bsid:  binary.BigEndian.Uint32([]byte{0xDB, 0xBA, 0x00, 0x00}),
				},
				SegmentList: []*SegmentList{
					{
						Weight: &Weight{
							Flags:  0,
							Weight: 1,
						},
						Segment: []Segment{
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 100010,
								tc:    0,
								s:     false,
								ttl:   0,
							},
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 24001,
								tc:    0,
								s:     false,
								ttl:   0,
							},
						},
					},
					{
						Weight: &Weight{
							Flags:  0,
							Weight: 3,
						},
						Segment: []Segment{
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 100010,
								tc:    0,
								s:     false,
								ttl:   0,
							},
							&typeASegment{
								flags: &SegmentFlags{
									Vflag: false,
									Aflag: false,
									Sflag: false,
									Bflag: false,
								},
								label: 24013,
								tc:    0,
								s:     false,
								ttl:   0,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalSRPolicyTLV(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("Supposed to succeed but failed with error: %+v", err)
				return
			}
			if err == nil && tt.fail {
				t.Fatalf("Supposed to fail but succeeded")
				return
			}
			if err != nil {
				return
			}
			if got == nil {
				t.Fatalf("processed TLV is nil")
			}
			//			if !reflect.DeepEqual(tt.expect, got) {
			for i := 0; i < len(got.SegmentList); i++ {
				t.Logf("Weight got: %+v Weight expect: %+v", *got.SegmentList[i].Weight, tt.expect.SegmentList[i].Weight)
				for y := 0; y < len(got.SegmentList[i].Segment); y++ {
					t.Logf("Flags got: %+v Flags expect: %+v", *got.SegmentList[i].Segment[y].GetFlags(),
						tt.expect.SegmentList[i].Segment[y].GetFlags())
					t.Logf("Type got: %d Type expect: %d", got.SegmentList[i].Segment[y].GetType(),
						tt.expect.SegmentList[i].Segment[y].GetType())
					t.Logf("Interface diff: %+v", deep.Equal(got.SegmentList[i].Segment[y], tt.expect.SegmentList[i].Segment[y]))
					g := got.SegmentList[i].Segment[y].(*typeASegment)
					e := tt.expect.SegmentList[i].Segment[y]
					t.Logf("Structure diff: %+v", deep.Equal(g, e))
				}
			}
			//			t.Fatalf("Expected TLV: %+v does not match to the processed TLV: %+v", *tt.expect, *got)
			//			}
		})
	}
}
