package bgp

import (
	"testing"
)

// TestUnmarshalBGPBaseAttributes_AllAttrTypes exercises the zero-coverage private
// unmarshal helpers (LocalPref, OriginatorID, ClusterList, ExtCommunity, AS4Path,
// AS4Aggregator) by supplying a raw path-attribute byte stream that contains each
// attribute type.
func TestUnmarshalBGPBaseAttributes_AllAttrTypes(t *testing.T) {
	// Format per RFC 4271 §4.3: [Flags 1B][Type 1B][Length 1B][Value ...]
	// Flags: 0x40 = well-known transitive; 0x80 = optional non-transitive;
	//        0xC0 = optional transitive.
	raw := []byte{
		// Type 1 – Origin (IGP = 0x00)
		0x40, 0x01, 0x01, 0x00,

		// Type 2 – ASPath: AS_SEQ of 1 AS (2-byte) = AS=1
		0x40, 0x02, 0x04, 0x02, 0x01, 0x00, 0x01,

		// Type 3 – NextHop = 10.0.0.1
		0x40, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x01,

		// Type 4 – MED = 10
		0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x0A,

		// Type 5 – LocalPref = 100   ← exercises unmarshalAttrLocalPref
		0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64,

		// Type 6 – AtomicAggregate (no value)
		0x40, 0x06, 0x00,

		// Type 9 – OriginatorID = 192.168.1.1   ← exercises unmarshalAttrOriginatorID
		0x80, 0x09, 0x04, 0xC0, 0xA8, 0x01, 0x01,

		// Type 10 – ClusterList: one cluster ID = 10.0.0.1   ← exercises unmarshalAttrClusterList
		0x80, 0x0A, 0x04, 0x0A, 0x00, 0x00, 0x01,

		// Type 16 – ExtCommunity: one 8-byte RT (type0/sub2/AS=1/admin=100)
		//   ← exercises unmarshalAttrExtCommunity
		0xC0, 0x10, 0x08, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64,

		// Type 17 – AS4Path: AS_SEQ of 1 AS4 = 65537   ← exercises unmarshalAttrAS4Path
		0xC0, 0x11, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01,

		// Type 18 – AS4Aggregator: AS4=1, IP=10.0.0.1   ← exercises unmarshalAttrAS4Aggregator
		0xC0, 0x12, 0x08, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01,
	}

	got, err := UnmarshalBGPBaseAttributes(raw)
	if err != nil {
		t.Fatalf("UnmarshalBGPBaseAttributes() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("got nil BaseAttributes")
	}

	if got.LocalPref != 100 {
		t.Errorf("LocalPref = %d, want 100", got.LocalPref)
	}
	if got.OriginatorID != "192.168.1.1" {
		t.Errorf("OriginatorID = %q, want %q", got.OriginatorID, "192.168.1.1")
	}
	if got.ClusterList == "" {
		t.Error("ClusterList should not be empty after parsing type 10")
	}
	if len(got.ExtCommunityList) == 0 {
		t.Error("ExtCommunityList should not be empty after parsing type 16")
	}
	if len(got.AS4Path) != 1 || got.AS4Path[0] != 65537 {
		t.Errorf("AS4Path = %v, want [65537]", got.AS4Path)
	}
	if len(got.AS4Aggregator) != 8 {
		t.Errorf("AS4Aggregator len = %d, want 8", len(got.AS4Aggregator))
	}
	if !got.IsAtomicAgg {
		t.Error("IsAtomicAgg should be true after parsing type 6")
	}
}

// TestBaseAttributes_Equal exercises the Equal method (currently 0% coverage).
func TestBaseAttributes_Equal(t *testing.T) {
	base := &BaseAttributes{
		Origin:        "igp",
		Nexthop:       "10.0.0.1",
		LocalPref:     100,
		OriginatorID:  "192.168.1.1",
		ClusterList:   "10.0.0.1",
		IsAtomicAgg:   true,
		CommunityList: []string{"1:1"},
	}

	t.Run("equal to itself", func(t *testing.T) {
		equal, diffs := base.Equal(base)
		if !equal {
			t.Errorf("Equal(self) = false, diffs: %v", diffs)
		}
	})

	t.Run("different origin", func(t *testing.T) {
		other := *base
		other.Origin = "egp"
		equal, diffs := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different Origin, want false")
		}
		if len(diffs) == 0 {
			t.Error("Expected diffs to be non-empty")
		}
	})

	t.Run("different nexthop", func(t *testing.T) {
		other := *base
		other.Nexthop = "10.0.0.2"
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different Nexthop, want false")
		}
	})

	t.Run("different LocalPref", func(t *testing.T) {
		other := *base
		other.LocalPref = 200
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different LocalPref, want false")
		}
	})

	t.Run("different OriginatorID", func(t *testing.T) {
		other := *base
		other.OriginatorID = "10.0.0.9"
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different OriginatorID, want false")
		}
	})

	t.Run("different ClusterList", func(t *testing.T) {
		other := *base
		other.ClusterList = "10.0.0.9"
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different ClusterList, want false")
		}
	})

	t.Run("different IsAtomicAgg", func(t *testing.T) {
		other := *base
		other.IsAtomicAgg = false
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different IsAtomicAgg, want false")
		}
	})

	t.Run("different CommunityList", func(t *testing.T) {
		other := *base
		other.CommunityList = []string{"2:2"}
		equal, _ := base.Equal(&other)
		if equal {
			t.Error("Equal() = true for different CommunityList, want false")
		}
	})
}

// TestUnmarshalBGPBaseAttributes_PathAttrErrors exercises error paths inside
// UnmarshalBGPPathAttributes (truncated headers/lengths).
func TestUnmarshalBGPBaseAttributes_PathAttrErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "single flag byte only (truncated header)",
			input: []byte{0x40},
		},
		{
			name: "extended-length flag but only 1 length byte",
			// Flags 0x50 = well-known transitive + extended-length, Type 1
			input: []byte{0x50, 0x01, 0xAA},
		},
		{
			name: "value shorter than declared length",
			// Flags 0x40, Type 1, length=4 but only 2 bytes follow
			input: []byte{0x40, 0x01, 0x04, 0x00, 0x00},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBGPBaseAttributes(tt.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
