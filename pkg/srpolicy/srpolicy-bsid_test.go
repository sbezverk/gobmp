package srpolicy

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/srv6"
)

// ============================================================================
// BSID JSON Marshaling/Unmarshaling Tests
// ============================================================================

func TestNoBSID_JSON(t *testing.T) {
	tests := []struct {
		name    string
		bsid    *noBSID
		wantErr bool
	}{
		{
			name: "noBSID with flags",
			bsid: &noBSID{
				flags: 0x01,
			},
			wantErr: false,
		},
		{
			name: "noBSID zero flags",
			bsid: &noBSID{
				flags: 0x00,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			data, err := json.Marshal(tt.bsid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test Unmarshal
			var result noBSID
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify
			if result.flags != tt.bsid.flags {
				t.Errorf("Unmarshal() flags = %v, want %v", result.flags, tt.bsid.flags)
			}
		})
	}
}

func TestNoBSID_Methods(t *testing.T) {
	bsid := &noBSID{flags: 0x80}

	if got := bsid.GetFlag(); got != 0x80 {
		t.Errorf("GetFlag() = %v, want %v", got, 0x80)
	}

	if got := bsid.GetType(); got != NOBSID {
		t.Errorf("GetType() = %v, want %v", got, NOBSID)
	}

	if got := bsid.GetBSID(); got != nil {
		t.Errorf("GetBSID() = %v, want nil", got)
	}
}

func TestLabelBSID_JSON(t *testing.T) {
	tests := []struct {
		name    string
		bsid    *labelBSID
		wantErr bool
	}{
		{
			name: "labelBSID standard",
			bsid: &labelBSID{
				flags: 0x01,
				bsid:  100000,
			},
			wantErr: false,
		},
		{
			name: "labelBSID max label",
			bsid: &labelBSID{
				flags: 0xFF,
				bsid:  1048575, // Max 20-bit MPLS label
			},
			wantErr: false,
		},
		{
			name: "labelBSID zero",
			bsid: &labelBSID{
				flags: 0x00,
				bsid:  0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			data, err := json.Marshal(tt.bsid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test Unmarshal
			var result labelBSID
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify
			if result.flags != tt.bsid.flags {
				t.Errorf("Unmarshal() flags = %v, want %v", result.flags, tt.bsid.flags)
			}
			if result.bsid != tt.bsid.bsid {
				t.Errorf("Unmarshal() bsid = %v, want %v", result.bsid, tt.bsid.bsid)
			}
		})
	}
}

func TestLabelBSID_Methods(t *testing.T) {
	bsid := &labelBSID{
		flags: 0x01,
		bsid:  100000,
	}

	if got := bsid.GetFlag(); got != 0x01 {
		t.Errorf("GetFlag() = %v, want %v", got, 0x01)
	}

	if got := bsid.GetType(); got != LABELBSID {
		t.Errorf("GetType() = %v, want %v", got, LABELBSID)
	}

	bsidBytes := bsid.GetBSID()
	if len(bsidBytes) != 4 {
		t.Errorf("GetBSID() length = %v, want 4", len(bsidBytes))
	}
	// Verify the uint32 encoding
	expected := []byte{0x00, 0x01, 0x86, 0xA0} // 100000 in big-endian
	for i, b := range bsidBytes {
		if b != expected[i] {
			t.Errorf("GetBSID()[%d] = %v, want %v", i, b, expected[i])
		}
	}
}

func TestSRv6BSID_JSON(t *testing.T) {
	tests := []struct {
		name    string
		bsid    *srv6BSID
		wantErr bool
	}{
		{
			name: "srv6BSID standard IPv6",
			bsid: &srv6BSID{
				flags: 0x01,
				bsid:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			},
			wantErr: false,
		},
		{
			name: "srv6BSID with endpoint behavior",
			bsid: &srv6BSID{
				flags: 0xFF,
				bsid:  []byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				eb:    &srv6.EndpointBehavior{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			data, err := json.Marshal(tt.bsid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test Unmarshal
			var result srv6BSID
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify
			if result.flags != tt.bsid.flags {
				t.Errorf("Unmarshal() flags = %v, want %v", result.flags, tt.bsid.flags)
			}
			if len(result.bsid) != len(tt.bsid.bsid) {
				t.Errorf("Unmarshal() bsid length = %v, want %v", len(result.bsid), len(tt.bsid.bsid))
			}
			for i := range result.bsid {
				if result.bsid[i] != tt.bsid.bsid[i] {
					t.Errorf("Unmarshal() bsid[%d] = %v, want %v", i, result.bsid[i], tt.bsid.bsid[i])
				}
			}
		})
	}
}

func TestSRv6BSID_Methods(t *testing.T) {
	eb := &srv6.EndpointBehavior{}
	bsid := &srv6BSID{
		flags: 0x80,
		bsid:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		eb:    eb,
	}

	if got := bsid.GetFlag(); got != 0x80 {
		t.Errorf("GetFlag() = %v, want %v", got, 0x80)
	}

	if got := bsid.GetType(); got != SRV6BSID {
		t.Errorf("GetType() = %v, want %v", got, SRV6BSID)
	}

	if got := bsid.GetBSID(); len(got) != 16 {
		t.Errorf("GetBSID() length = %v, want 16", len(got))
	}

	if got := bsid.GetEndpointBehavior(); got != eb {
		t.Errorf("GetEndpointBehavior() = %v, want %v", got, eb)
	}
}

func TestBindingSID_JSON(t *testing.T) {
	tests := []struct {
		name    string
		bsid    *BindingSID
		wantErr bool
	}{
		{
			name: "BindingSID with noBSID",
			bsid: &BindingSID{
				Type: NOBSID,
				BSID: &noBSID{flags: 0x01},
			},
			wantErr: false,
		},
		{
			name: "BindingSID with labelBSID",
			bsid: &BindingSID{
				Type: LABELBSID,
				BSID: &labelBSID{flags: 0x01, bsid: 100000},
			},
			wantErr: false,
		},
		{
			name: "BindingSID with srv6BSID",
			bsid: &BindingSID{
				Type: SRV6BSID,
				BSID: &srv6BSID{
					flags: 0xFF,
					bsid:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Marshal
			data, err := json.Marshal(tt.bsid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			t.Logf("Marshaled JSON: %s", string(data))

			// Test Unmarshal
			var result BindingSID
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Verify type
			if result.Type != tt.bsid.Type {
				t.Errorf("Unmarshal() Type = %v, want %v", result.Type, tt.bsid.Type)
			}

			// Verify BSID interface
			if result.BSID.GetType() != tt.bsid.BSID.GetType() {
				t.Errorf("Unmarshal() BSID type = %v, want %v", result.BSID.GetType(), tt.bsid.BSID.GetType())
			}
		})
	}
}

func TestBindingSID_JSON_InvalidType(t *testing.T) {
	// Test unknown BSID type
	invalidJSON := `{"bsid_type": 99, "bsid": {}}`
	var bsid BindingSID
	err := json.Unmarshal([]byte(invalidJSON), &bsid)
	if err == nil {
		t.Error("Expected error for unknown bsid type, got nil")
	}
}

func TestBindingSID_MarshalJSON_InvalidType(t *testing.T) {
	// Create BindingSID with invalid type
	bsid := &BindingSID{
		Type: BSIDType(99),
		BSID: &noBSID{},
	}

	_, err := json.Marshal(bsid)
	if err == nil {
		t.Error("Expected error for unknown bsid type in Marshal, got nil")
	}
}
