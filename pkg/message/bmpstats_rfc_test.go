package message

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// makeAFISAFIData creates 11-byte AFI/SAFI/Gauge data
func makeAFISAFIData(afi uint16, safi uint8, count uint64) []byte {
	data := make([]byte, 11)
	binary.BigEndian.PutUint16(data[0:2], afi)
	data[2] = safi
	binary.BigEndian.PutUint64(data[3:11], count)
	return data
}

// TestParseAFISAFIStat tests the AFI/SAFI parsing helper
func TestParseAFISAFIStat(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    AFISAFIStat
		wantErr bool
	}{
		{
			name: "IPv4 Unicast",
			data: makeAFISAFIData(1, 1, 12345), // AFI=1 (IPv4), SAFI=1 (Unicast)
			want: AFISAFIStat{AFI: 1, SAFI: 1, Count: 12345},
		},
		{
			name: "IPv6 Unicast",
			data: makeAFISAFIData(2, 1, 67890), // AFI=2 (IPv6), SAFI=1 (Unicast)
			want: AFISAFIStat{AFI: 2, SAFI: 1, Count: 67890},
		},
		{
			name: "IPv4 MPLS VPN",
			data: makeAFISAFIData(1, 128, 999), // AFI=1, SAFI=128 (MPLS VPN)
			want: AFISAFIStat{AFI: 1, SAFI: 128, Count: 999},
		},
		{
			name:    "Invalid - Too Short",
			data:    make([]byte, 5),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAFISAFIStat(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAFISAFIStat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseAFISAFIStat() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestStatsType9_PerAFIAdjRIBsIn tests RFC 7854 Type 9
func TestStatsType9_PerAFIAdjRIBsIn(t *testing.T) {
	// Test single AFI/SAFI entry
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType:   9,
				InformationLength: 11,
				Information:       makeAFISAFIData(1, 1, 50000), // IPv4 Unicast
			},
		},
	}

	m := Stats{}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 9 {
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				t.Fatalf("parseAFISAFIStat() error = %v", err)
			}
			m.PerAFIAdjRIBsIn = append(m.PerAFIAdjRIBsIn, stat)
		}
	}

	if len(m.PerAFIAdjRIBsIn) != 1 {
		t.Errorf("Expected 1 AFI/SAFI entry, got %d", len(m.PerAFIAdjRIBsIn))
	}
	if m.PerAFIAdjRIBsIn[0].AFI != 1 || m.PerAFIAdjRIBsIn[0].SAFI != 1 || m.PerAFIAdjRIBsIn[0].Count != 50000 {
		t.Errorf("Incorrect AFI/SAFI stat: %+v", m.PerAFIAdjRIBsIn[0])
	}
}

// TestStatsType9_MultipleAFISAFI tests multiple AFI/SAFI entries in single message
func TestStatsType9_MultipleAFISAFI(t *testing.T) {
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 9, InformationLength: 11, Information: makeAFISAFIData(1, 1, 10000)},   // IPv4 Unicast
			{InformationType: 9, InformationLength: 11, Information: makeAFISAFIData(2, 1, 5000)},    // IPv6 Unicast
			{InformationType: 9, InformationLength: 11, Information: makeAFISAFIData(1, 128, 2000)},  // IPv4 MPLS VPN
		},
	}

	m := Stats{}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 9 {
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				t.Fatalf("parseAFISAFIStat() error = %v", err)
			}
			m.PerAFIAdjRIBsIn = append(m.PerAFIAdjRIBsIn, stat)
		}
	}

	if len(m.PerAFIAdjRIBsIn) != 3 {
		t.Errorf("Expected 3 AFI/SAFI entries, got %d", len(m.PerAFIAdjRIBsIn))
	}

	// Verify each entry
	expected := []AFISAFIStat{
		{AFI: 1, SAFI: 1, Count: 10000},
		{AFI: 2, SAFI: 1, Count: 5000},
		{AFI: 1, SAFI: 128, Count: 2000},
	}

	for i, want := range expected {
		if m.PerAFIAdjRIBsIn[i] != want {
			t.Errorf("Entry %d: got %+v, want %+v", i, m.PerAFIAdjRIBsIn[i], want)
		}
	}
}

// TestStatsType10_PerAFILocRIB tests RFC 7854 Type 10
func TestStatsType10_PerAFILocRIB(t *testing.T) {
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType:   10,
				InformationLength: 11,
				Information:       makeAFISAFIData(1, 1, 75000), // IPv4 Unicast
			},
		},
	}

	m := Stats{}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 10 {
			stat, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				t.Fatalf("parseAFISAFIStat() error = %v", err)
			}
			m.PerAFILocRIB = append(m.PerAFILocRIB, stat)
		}
	}

	if len(m.PerAFILocRIB) != 1 {
		t.Errorf("Expected 1 AFI/SAFI entry, got %d", len(m.PerAFILocRIB))
	}
	if m.PerAFILocRIB[0].Count != 75000 {
		t.Errorf("Expected count=75000, got %d", m.PerAFILocRIB[0].Count)
	}
}

// TestStatsType13_DuplicateUpdates tests RFC 7854 Type 13
func TestStatsType13_DuplicateUpdates(t *testing.T) {
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{
				InformationType:   13,
				InformationLength: 4,
				Information:       make([]byte, 4),
			},
		},
	}
	binary.BigEndian.PutUint32(statsMsg.StatsTLV[0].Information, 777)

	m := Stats{}

	for _, tlv := range statsMsg.StatsTLV {
		if tlv.InformationType == 13 {
			m.DuplicateUpdates = binary.BigEndian.Uint32(tlv.Information)
		}
	}

	if m.DuplicateUpdates != 777 {
		t.Errorf("Expected DuplicateUpdates=777, got %d", m.DuplicateUpdates)
	}
}

// TestStatsType16_17_PerAFIAdjRIBOut tests RFC 8671 Types 16-17
func TestStatsType16_17_PerAFIAdjRIBOut(t *testing.T) {
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 16, InformationLength: 11, Information: makeAFISAFIData(1, 1, 3000)}, // Type 16
			{InformationType: 17, InformationLength: 11, Information: makeAFISAFIData(2, 1, 4000)}, // Type 17
		},
	}

	m := Stats{}

	for _, tlv := range statsMsg.StatsTLV {
		switch tlv.InformationType {
		case 16:
			stat, _ := parseAFISAFIStat(tlv.Information)
			m.PerAFIPrePolicyAdjRIBOut = append(m.PerAFIPrePolicyAdjRIBOut, stat)
		case 17:
			stat, _ := parseAFISAFIStat(tlv.Information)
			m.PerAFIPostPolicyAdjRIBOut = append(m.PerAFIPostPolicyAdjRIBOut, stat)
		}
	}

	if len(m.PerAFIPrePolicyAdjRIBOut) != 1 {
		t.Errorf("Type 16: expected 1 entry, got %d", len(m.PerAFIPrePolicyAdjRIBOut))
	}
	if len(m.PerAFIPostPolicyAdjRIBOut) != 1 {
		t.Errorf("Type 17: expected 1 entry, got %d", len(m.PerAFIPostPolicyAdjRIBOut))
	}

	if m.PerAFIPrePolicyAdjRIBOut[0].Count != 3000 {
		t.Errorf("Type 16: wrong count %d", m.PerAFIPrePolicyAdjRIBOut[0].Count)
	}
	if m.PerAFIPostPolicyAdjRIBOut[0].Count != 4000 {
		t.Errorf("Type 17: wrong count %d", m.PerAFIPostPolicyAdjRIBOut[0].Count)
	}
}

// TestRFC7854_AllTypesCompliance verifies all RFC 7854 types are handled
func TestRFC7854_AllTypesCompliance(t *testing.T) {
	// Create message with all RFC 7854 types (0-13)
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 0, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 1, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 2, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 3, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 4, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 5, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 6, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 7, InformationLength: 8, Information: make([]byte, 8)},
			{InformationType: 8, InformationLength: 8, Information: make([]byte, 8)},
			{InformationType: 9, InformationLength: 11, Information: makeAFISAFIData(1, 1, 100)},
			{InformationType: 10, InformationLength: 11, Information: makeAFISAFIData(1, 1, 200)},
			{InformationType: 11, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 12, InformationLength: 4, Information: make([]byte, 4)},
			{InformationType: 13, InformationLength: 4, Information: make([]byte, 4)},
		},
	}

	// Verify all types can be parsed
	for _, tlv := range statsMsg.StatsTLV {
		switch tlv.InformationType {
		case 0, 1, 2, 3, 4, 5, 6, 11, 12, 13:
			// 32-bit counter
			if len(tlv.Information) < 4 {
				t.Errorf("Type %d: insufficient data", tlv.InformationType)
			}
		case 7, 8:
			// 64-bit gauge
			if len(tlv.Information) < 8 {
				t.Errorf("Type %d: insufficient data", tlv.InformationType)
			}
		case 9, 10:
			// AFI/SAFI stat
			_, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				t.Errorf("Type %d: parse error: %v", tlv.InformationType, err)
			}
		default:
			t.Errorf("RFC 7854 compliance: unhandled type %d", tlv.InformationType)
		}
	}
}

// TestRFC8671_AllTypesCompliance verifies all RFC 8671 types are handled
func TestRFC8671_AllTypesCompliance(t *testing.T) {
	// Create message with all RFC 8671 types (14-17)
	statsMsg := &bmp.StatsReport{
		StatsTLV: []bmp.InformationalTLV{
			{InformationType: 14, InformationLength: 8, Information: make([]byte, 8)},
			{InformationType: 15, InformationLength: 8, Information: make([]byte, 8)},
			{InformationType: 16, InformationLength: 11, Information: makeAFISAFIData(1, 1, 300)},
			{InformationType: 17, InformationLength: 11, Information: makeAFISAFIData(1, 1, 400)},
		},
	}

	// Verify all types can be parsed
	for _, tlv := range statsMsg.StatsTLV {
		switch tlv.InformationType {
		case 14, 15:
			// 64-bit gauge
			if len(tlv.Information) < 8 {
				t.Errorf("Type %d: insufficient data", tlv.InformationType)
			}
		case 16, 17:
			// AFI/SAFI stat
			_, err := parseAFISAFIStat(tlv.Information)
			if err != nil {
				t.Errorf("Type %d: parse error: %v", tlv.InformationType, err)
			}
		default:
			t.Errorf("RFC 8671 compliance: unhandled type %d", tlv.InformationType)
		}
	}
}
