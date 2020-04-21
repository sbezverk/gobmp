package bgp

import (
	"reflect"
	"strings"
	"testing"
)

func TestGetAttrASPath(t *testing.T) {
	tests := []struct {
		name       string
		update     *Update
		as4Capable bool
		expect     []uint32
	}{
		{
			name:   "Empty, no attribute AS_PATH",
			update: &Update{},
			expect: []uint32{},
		},
		{
			name: "single segment path 1 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 1, 0x2, 0x41},
					},
				},
			},
			expect: []uint32{577},
		},
		{
			name: "single segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 2, 0x2, 0x41, 0x2, 0x42},
					},
				},
			},
			expect: []uint32{577, 578},
		},
		{
			name: "2 segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{1, 1, 0x2, 0x41, 1, 1, 0x2, 0x42},
					},
				},
			},
			expect: []uint32{577, 578},
		},
		{
			name: "panic case #1",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{2, 1, 0, 0, 28, 32},
					},
				},
			},
			expect: []uint32{7200},
		},
		{
			name: "panic case #2",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{2, 2, 0, 0, 28, 32, 0, 1, 134, 160},
					},
				},
			},
			expect: []uint32{7200, 100000},
		},
		{
			name: "panic case #3",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{0x02, 0x06, 0x73, 0xfb, 0x32, 0xe6, 0x93, 0x1e, 0x91, 0x54, 0xdd, 0x78, 0xdd, 0x78},
					},
				},
			},
			expect: []uint32{29691, 13030, 37662, 37204, 56696, 56696},
		},
		{
			name: "panic case #4",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 2,
						Attribute:     []byte{0x02, 0x06, 0x00, 0x00, 0xbf, 0xee, 0x00, 0x00, 0xd0, 0x6c, 0x00, 0x00, 0x1b, 0x1b, 0x00, 0x00, 0x05, 0x13, 0x00, 0x00, 0x0b, 0x62, 0x00, 0x00, 0x51, 0xcc},
					},
				},
			},
			expect: []uint32{49134, 53356, 6939, 1299, 2914, 20940},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.update.GetAttrASPath()
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Expect list of ASes %+v does not match received list %+v", tt.expect, got)
			}
		})
	}
}

func TestGetAttrAS4Path(t *testing.T) {
	tests := []struct {
		name   string
		update *Update
		expect []uint32
	}{
		{
			name:   "Empty, no attribute AS_PATH",
			update: &Update{},
			expect: []uint32{},
		},
		{
			name: "AS4 single segment path 1 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 17,
						Attribute:     []byte{1, 1, 0x0, 0x0f, 0x42, 0x40},
					},
				},
			},
			expect: []uint32{1000000},
		},
		{
			name: "AS4 single segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 17,
						Attribute:     []byte{1, 2, 0x0, 0x0f, 0x42, 0x40, 0x0, 0x0f, 0x42, 0x41},
					},
				},
			},
			expect: []uint32{1000000, 1000001},
		},
		{
			name: "AS4 2 segment path 2 AS",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 17,
						Attribute:     []byte{1, 1, 0x0, 0x0f, 0x42, 0x40, 1, 1, 0x0, 0x0f, 0x42, 0x41},
					},
				},
			},
			expect: []uint32{1000000, 1000001},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.update.GetAttrAS4Path()
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Expect list of ASes %+v does not match received list %+v", tt.expect, got)
			}
		})
	}
}

func TestGetAttrCommunityString(t *testing.T) {
	tests := []struct {
		name   string
		update *Update
		expect string
	}{
		{
			name:   "Empty, no attribute Community",
			update: &Update{},
			expect: "",
		},
		{
			name: "1 Standard community 0:0",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 8,
						Attribute:     []byte{0, 0, 0, 0},
					},
				},
			},
			expect: "0:0",
		},
		{
			name: "1 Standard community 10:10",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 8,
						Attribute:     []byte{0, 10, 0, 10},
					},
				},
			},
			expect: "10:10",
		},
		{
			name: "2 Standard communities 10:10, 20:20",
			update: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 8,
						Attribute:     []byte{0, 10, 0, 10, 0, 20, 0, 20},
					},
				},
			},
			expect: "10:10, 20:20",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.update.GetAttrCommunityString()
			if !reflect.DeepEqual(tt.expect, got) {
				t.Errorf("Expect list of Standard Communities %s does not match received list %s", tt.expect, got)
			}
		})
	}
}

func TestGetAttrExtCommunity(t *testing.T) {
	subtype := uint8(2)
	subtypeColor := uint8(0xb)
	tests := []struct {
		name      string
		input     *Update
		expect    []ExtCommunity
		expectStr string
		fail      bool
	}{
		{
			name: "extCommunity 1",
			input: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 16,
						Attribute:     []byte{0x00, 0x02, 0x02, 0x41, 0x00, 0x00, 0xfd, 0xec},
					},
				},
			},
			expect: []ExtCommunity{
				{
					Type:    0,
					SubType: &subtype,
					Value:   []byte{0x02, 0x41, 0x00, 0x00, 0xfd, 0xec},
				},
			},
			expectStr: "rt=577:65004",
			fail:      false,
		},
		{
			name: "2 extended Communities",
			input: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 16,
						Attribute:     []byte{0x00, 0x02, 0x02, 0x41, 0x00, 0x00, 0xfd, 0xec, 0x00, 0x02, 0x02, 0x41, 0x00, 0x00, 0xfd, 0xed},
					},
				},
			},
			expect: []ExtCommunity{
				{
					Type:    0,
					SubType: &subtype,
					Value:   []byte{0x02, 0x41, 0x00, 0x00, 0xfd, 0xec},
				},
				{
					Type:    0,
					SubType: &subtype,
					Value:   []byte{0x02, 0x41, 0x00, 0x00, 0xfd, 0xed},
				},
			},
			expectStr: "rt=577:65004,rt=577:65005",
			fail:      false,
		},
		{
			name: "color extCommunity",
			input: &Update{
				PathAttributes: []PathAttribute{
					{
						AttributeType: 16,
						Attribute:     []byte{0x03, 0x0b, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00},
					},
				},
			},
			expect: []ExtCommunity{
				{
					Type:    3,
					SubType: &subtypeColor,
					Value:   []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00},
				},
			},
			expectStr: "color=50331648",
			fail:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.input.GetAttrExtCommunity()
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.expect) {
					t.Errorf("Expected extCommunity %+v does not match to actual extCommunity %+v", tt.expect, got)
				}
				cStr := strings.Split(tt.expectStr, ",")
				for i, c := range got {
					if strings.Compare(c.String(), cStr[i]) != 0 {
						t.Errorf("Expected extCommunity string %s does not match to actual extCommunity %+v", cStr[i], c.String())
					}
				}
			}
		})
	}
}
