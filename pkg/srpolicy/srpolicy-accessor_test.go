package srpolicy

import (
	"encoding/json"
	"testing"
)

// TestWeight_UnmarshalJSON_RoundTrip verifies Weight JSON round-trip preserves
// both flags and weight fields correctly.
func TestWeight_UnmarshalJSON_RoundTrip(t *testing.T) {
	w := &Weight{Flags: 3, Weight: 200}
	data, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var got Weight
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if got.Flags != 3 {
		t.Errorf("Flags = %d, want 3", got.Flags)
	}
	if got.Weight != 200 {
		t.Errorf("Weight = %d, want 200", got.Weight)
	}
}

// TestWeight_UnmarshalJSON_BadWeight verifies UnmarshalJSON returns an error
// when the weight field contains an invalid value.
func TestWeight_UnmarshalJSON_BadWeight(t *testing.T) {
	var w Weight
	if err := w.UnmarshalJSON([]byte(`{"weight":"notanumber"}`)); err == nil {
		t.Error("expected error for bad weight value, got nil")
	}
}

// TestGetFlags_AllTypes verifies GetFlags returns a non-nil SegmentFlags for each
// implemented segment type after a successful parse.
func TestGetFlags_AllTypes(t *testing.T) {
	tests := []struct {
		name    string
		unmarshal func() (Segment, error)
	}{
		{
			name: "TypeB GetFlags",
			unmarshal: func() (Segment, error) {
				// 18 bytes: flags(1) + reserved(1) + SRv6 SID(16)
				b := make([]byte, 18)
				b[0] = 0x00 // flags
				return UnmarshalTypeBSegment(b)
			},
		},
		{
			name: "TypeC GetFlags",
			unmarshal: func() (Segment, error) {
				// 6 bytes: flags(1) + srAlgorithm(1) + IPv4(4)
				b := []byte{0x00, 0x00, 10, 0, 0, 1}
				return UnmarshalTypeCSegment(b)
			},
		},
		{
			name: "TypeD GetFlags",
			unmarshal: func() (Segment, error) {
				// 18 bytes: flags(1) + srAlgorithm(1) + IPv6(16)
				b := make([]byte, 18)
				return UnmarshalTypeDSegment(b)
			},
		},
		{
			name: "TypeE GetFlags",
			unmarshal: func() (Segment, error) {
				// 10 bytes: flags(1) + reserved(1) + LocalInterfaceID(4) + IPv4(4)
				b := make([]byte, 10)
				return UnmarshalTypeESegment(b)
			},
		},
		{
			name: "TypeF GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + reserved(1) + LocalIPv4(4) + RemoteIPv4(4) = 10 bytes
				b := make([]byte, 10)
				return UnmarshalTypeFSegment(b)
			},
		},
		{
			name: "TypeG GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + reserved(1) + LocalIPv6(16) + LocalIfID(4) + RemoteIPv6(16) + RemoteIfID(4) = 42 bytes
				b := make([]byte, 42)
				return UnmarshalTypeGSegment(b)
			},
		},
		{
			name: "TypeH GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + reserved(1) + LocalIPv6(16) + RemoteIPv6(16) = 34 bytes
				b := make([]byte, 34)
				return UnmarshalTypeHSegment(b)
			},
		},
		{
			name: "TypeI GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + reserved(1) + IPv6(16) + SRv6EndpointBehavior(4) = 22 bytes
				b := make([]byte, 22)
				return UnmarshalTypeISegment(b)
			},
		},
		{
			name: "TypeJ GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + srAlgorithm(1) + LocalIfID(4) + LocalIPv6(16) + RemoteIfID(4) + RemoteIPv6(16) = 42 bytes
				b := make([]byte, 42)
				return UnmarshalTypeJSegment(b)
			},
		},
		{
			name: "TypeK GetFlags",
			unmarshal: func() (Segment, error) {
				// flags(1) + srAlgorithm(1) + LocalIPv6(16) + RemoteIPv6(16) = 34 bytes
				b := make([]byte, 34)
				return UnmarshalTypeKSegment(b)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seg, err := tt.unmarshal()
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if seg.GetFlags() == nil {
				t.Error("GetFlags() returned nil, want non-nil SegmentFlags")
			}
		})
	}
}

// TestGetType_TypeH verifies GetType returns TypeH for a typeHSegment.
func TestGetType_TypeH(t *testing.T) {
	b := make([]byte, 34) // flags(1) + reserved(1) + LocalIPv6(16) + RemoteIPv6(16)
	seg, err := UnmarshalTypeHSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalTypeHSegment: %v", err)
	}
	if seg.GetType() != TypeH {
		t.Errorf("GetType() = %d, want %d", seg.GetType(), TypeH)
	}
}

// TestGetType_TypeJ verifies GetType returns TypeJ for a typeJSegment.
func TestGetType_TypeJ(t *testing.T) {
	b := make([]byte, 42) // flags(1) + srAlgorithm(1) + LocalIfID(4) + LocalIPv6(16) + RemoteIfID(4) + RemoteIPv6(16)
	seg, err := UnmarshalTypeJSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalTypeJSegment: %v", err)
	}
	if seg.GetType() != TypeJ {
		t.Errorf("GetType() = %d, want %d", seg.GetType(), TypeJ)
	}
}

// TestGetType_TypeK verifies GetType returns TypeK for a typeKSegment.
func TestGetType_TypeK(t *testing.T) {
	b := make([]byte, 34) // flags(1) + srAlgorithm(1) + LocalIPv6(16) + RemoteIPv6(16)
	seg, err := UnmarshalTypeKSegment(b)
	if err != nil {
		t.Fatalf("UnmarshalTypeKSegment: %v", err)
	}
	if seg.GetType() != TypeK {
		t.Errorf("GetType() = %d, want %d", seg.GetType(), TypeK)
	}
}

// TestUnmarshalJSON_BadJSON_AllTypes verifies each segment type returns an error
// when UnmarshalJSON receives invalid JSON.
func TestUnmarshalJSON_BadJSON_AllTypes(t *testing.T) {
	bad := []byte(`{invalid}`)

	t.Run("TypeB", func(t *testing.T) {
		s := &typeBSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeC", func(t *testing.T) {
		s := &typeCSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeD", func(t *testing.T) {
		s := &typeDSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeE", func(t *testing.T) {
		s := &typeESegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeF", func(t *testing.T) {
		s := &typeFSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeG", func(t *testing.T) {
		s := &typeGSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeH", func(t *testing.T) {
		s := &typeHSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeI", func(t *testing.T) {
		s := &typeISegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeJ", func(t *testing.T) {
		s := &typeJSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
	t.Run("TypeK", func(t *testing.T) {
		s := &typeKSegment{}
		if err := s.UnmarshalJSON(bad); err == nil {
			t.Error("expected error for bad JSON, got nil")
		}
	})
}

// TestUnmarshalJSONObj_BadFieldValues verifies unmarshalJSONObj error paths when
// individual JSON fields contain invalid values.
func TestUnmarshalJSONObj_BadFieldValues(t *testing.T) {
	t.Run("TypeC bad flags", func(t *testing.T) {
		s := &typeCSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`"notanobject"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeC bad ipv4_address length", func(t *testing.T) {
		s := &typeCSegment{}
		// Valid flags, but IPv4 address with wrong length (5 bytes instead of 4)
		raw := map[string]json.RawMessage{
			"ipv4_address": json.RawMessage(`[1,2,3,4,5]`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong IPv4 address length, got nil")
		}
	})
	t.Run("TypeD bad ipv6_address length", func(t *testing.T) {
		s := &typeDSegment{}
		raw := map[string]json.RawMessage{
			"ipv6_address": json.RawMessage(`[1,2,3]`), // wrong length
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong IPv6 address length, got nil")
		}
	})
	t.Run("TypeE bad flags", func(t *testing.T) {
		s := &typeESegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`), // wrong type
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeF bad flags", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeG bad flags", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeH bad flags", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeI bad flags", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})

	// =========================================================================
	// Type A unmarshalJSONObj error paths
	// =========================================================================
	t.Run("TypeA bad flags", func(t *testing.T) {
		s := &typeASegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeA bad label", func(t *testing.T) {
		s := &typeASegment{}
		raw := map[string]json.RawMessage{
			"label": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad label value, got nil")
		}
	})
	t.Run("TypeA bad tc", func(t *testing.T) {
		s := &typeASegment{}
		raw := map[string]json.RawMessage{
			"tc": json.RawMessage(`"notabyte"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad tc value, got nil")
		}
	})
	t.Run("TypeA bad s", func(t *testing.T) {
		s := &typeASegment{}
		raw := map[string]json.RawMessage{
			"s": json.RawMessage(`"notabool"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad s value, got nil")
		}
	})
	t.Run("TypeA bad ttl", func(t *testing.T) {
		s := &typeASegment{}
		raw := map[string]json.RawMessage{
			"ttl": json.RawMessage(`"notabyte"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad ttl value, got nil")
		}
	})

	// =========================================================================
	// Type B unmarshalJSONObj error paths
	// =========================================================================
	t.Run("TypeB bad flags", func(t *testing.T) {
		s := &typeBSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeB bad srv6_sid", func(t *testing.T) {
		s := &typeBSegment{}
		raw := map[string]json.RawMessage{
			"srv6_sid": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad srv6_sid value, got nil")
		}
	})
	t.Run("TypeB srv6_sid wrong length", func(t *testing.T) {
		s := &typeBSegment{}
		raw := map[string]json.RawMessage{
			"srv6_sid": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong srv6_sid length, got nil")
		}
	})

	// =========================================================================
	// Type C unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeC bad sr_algorithm", func(t *testing.T) {
		s := &typeCSegment{}
		raw := map[string]json.RawMessage{
			"sr_algorithm": json.RawMessage(`"notabyte"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sr_algorithm, got nil")
		}
	})
	t.Run("TypeC bad sid", func(t *testing.T) {
		s := &typeCSegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})
	t.Run("TypeC bad ipv4_address decode", func(t *testing.T) {
		s := &typeCSegment{}
		raw := map[string]json.RawMessage{
			"ipv4_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad ipv4_address decode, got nil")
		}
	})

	// =========================================================================
	// Type D unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeD bad flags", func(t *testing.T) {
		s := &typeDSegment{}
		raw := map[string]json.RawMessage{
			"flags": json.RawMessage(`123`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad flags value, got nil")
		}
	})
	t.Run("TypeD bad sr_algorithm", func(t *testing.T) {
		s := &typeDSegment{}
		raw := map[string]json.RawMessage{
			"sr_algorithm": json.RawMessage(`"notabyte"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sr_algorithm, got nil")
		}
	})
	t.Run("TypeD bad ipv6_address decode", func(t *testing.T) {
		s := &typeDSegment{}
		raw := map[string]json.RawMessage{
			"ipv6_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad ipv6_address decode, got nil")
		}
	})
	t.Run("TypeD bad sid", func(t *testing.T) {
		s := &typeDSegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})

	// =========================================================================
	// Type E unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeE bad local_interface_id", func(t *testing.T) {
		s := &typeESegment{}
		raw := map[string]json.RawMessage{
			"local_interface_id": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad local_interface_id, got nil")
		}
	})
	t.Run("TypeE bad ipv4_address decode", func(t *testing.T) {
		s := &typeESegment{}
		raw := map[string]json.RawMessage{
			"ipv4_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad ipv4_address decode, got nil")
		}
	})
	t.Run("TypeE bad ipv4_address length", func(t *testing.T) {
		s := &typeESegment{}
		raw := map[string]json.RawMessage{
			"ipv4_address": json.RawMessage(`[1,2,3,4,5]`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong ipv4_address length, got nil")
		}
	})
	t.Run("TypeE bad sid", func(t *testing.T) {
		s := &typeESegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})

	// =========================================================================
	// Type F unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeF bad local_ipv4_address decode", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv4_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad local_ipv4_address decode, got nil")
		}
	})
	t.Run("TypeF bad local_ipv4_address length", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv4_address": json.RawMessage(`[1,2,3,4,5]`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong local_ipv4_address length, got nil")
		}
	})
	t.Run("TypeF bad remote_ipv4_address decode", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv4_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad remote_ipv4_address decode, got nil")
		}
	})
	t.Run("TypeF bad remote_ipv4_address length", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv4_address": json.RawMessage(`[1,2,3,4,5]`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong remote_ipv4_address length, got nil")
		}
	})
	t.Run("TypeF bad sid", func(t *testing.T) {
		s := &typeFSegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})

	// =========================================================================
	// Type G unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeG bad local_interface_id", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"local_interface_id": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad local_interface_id, got nil")
		}
	})
	t.Run("TypeG bad local_ipv6_address decode", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv6_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad local_ipv6_address decode, got nil")
		}
	})
	t.Run("TypeG bad local_ipv6_address length", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv6_address": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong local_ipv6_address length, got nil")
		}
	})
	t.Run("TypeG bad remote_interface_id", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"remote_interface_id": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad remote_interface_id, got nil")
		}
	})
	t.Run("TypeG bad remote_ipv6_address decode", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv6_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad remote_ipv6_address decode, got nil")
		}
	})
	t.Run("TypeG bad remote_ipv6_address length", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv6_address": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong remote_ipv6_address length, got nil")
		}
	})
	t.Run("TypeG bad sid", func(t *testing.T) {
		s := &typeGSegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})

	// =========================================================================
	// Type H unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeH bad local_ipv6_address decode", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv6_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad local_ipv6_address decode, got nil")
		}
	})
	t.Run("TypeH bad local_ipv6_address length", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"local_ipv6_address": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong local_ipv6_address length, got nil")
		}
	})
	t.Run("TypeH bad remote_ipv6_address decode", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv6_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad remote_ipv6_address decode, got nil")
		}
	})
	t.Run("TypeH bad remote_ipv6_address length", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"remote_ipv6_address": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong remote_ipv6_address length, got nil")
		}
	})
	t.Run("TypeH bad sid", func(t *testing.T) {
		s := &typeHSegment{}
		raw := map[string]json.RawMessage{
			"sid": json.RawMessage(`"notanumber"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sid value, got nil")
		}
	})

	// =========================================================================
	// Type I unmarshalJSONObj additional error paths
	// =========================================================================
	t.Run("TypeI bad sr_algorithm", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"sr_algorithm": json.RawMessage(`"notabyte"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad sr_algorithm, got nil")
		}
	})
	t.Run("TypeI bad ipv6_node_address decode", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"ipv6_node_address": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad ipv6_node_address decode, got nil")
		}
	})
	t.Run("TypeI bad ipv6_node_address length", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"ipv6_node_address": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong ipv6_node_address length, got nil")
		}
	})
	t.Run("TypeI bad srv6_sid decode", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"srv6_sid": json.RawMessage(`"not_base64!!"`),
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for bad srv6_sid decode, got nil")
		}
	})
	t.Run("TypeI bad srv6_sid length", func(t *testing.T) {
		s := &typeISegment{}
		raw := map[string]json.RawMessage{
			"srv6_sid": json.RawMessage(`"AQID"`), // 3 bytes
		}
		if err := s.unmarshalJSONObj(raw); err == nil {
			t.Error("expected error for wrong srv6_sid length, got nil")
		}
	})
}
