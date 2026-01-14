package message

import (
	"sync"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestGetTableKey verifies table key generation
// Per RFC 9069 Section 4: Table key = BGP-ID + Peer Distinguisher
func TestGetTableKey(t *testing.T) {
	tests := []struct {
		name     string
		bgpID    []byte
		rd       []byte
		expected string
	}{
		{
			name:     "IPv4 no RD (PeerType0)",
			bgpID:    []byte{10, 0, 0, 1},
			rd:       []byte{0, 0, 0, 0, 0, 0, 0, 0},
			expected: "10.0.0.10:0",
		},
		{
			name:     "IPv4 with RD Type 1",
			bgpID:    []byte{192, 168, 1, 1},
			rd:       []byte{0, 1, 192, 168, 1, 1, 0, 100}, // Type 1: IP:ASN
			expected: "192.168.1.1192.168.1.1:100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := &bmp.PerPeerHeader{
				PeerBGPID:         tt.bgpID,
				PeerDistinguisher: tt.rd,
			}

			got := ph.GetTableKey()
			if got != tt.expected {
				t.Errorf("GetTableKey() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestPerTableAddPath verifies AddPath capability is tracked per-table
// Per RFC 7911 Section 3: AddPath capability is per BGP session
func TestPerTableAddPath(t *testing.T) {
	// Create mock publisher
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	// Simulate two different tables with different AddPath capabilities
	table1Key := "10.0.0.10:0"
	table2Key := "192.168.1.165000:100"

	// Table 1: has AddPath for IPv4 Unicast (AFI/SAFI 1/1)
	p.tableLock.Lock()
	p.tableProperties[table1Key] = PerTableProperties{
		addPathCapable: map[int]bool{
			65537: true, // AFI 1, SAFI 1 -> key = 1<<16 + 1 = 65537
		},
	}

	// Table 2: has AddPath for EVPN (AFI/SAFI 25/70)
	p.tableProperties[table2Key] = PerTableProperties{
		addPathCapable: map[int]bool{
			1638470: true, // AFI 25, SAFI 70 -> key = 25<<16 + 70
		},
	}
	p.tableLock.Unlock()

	// Test table 1 capability
	cap1 := p.GetAddPathCapability(table1Key)
	if !cap1[65537] {
		t.Errorf("Table 1 should have AddPath for IPv4 Unicast")
	}
	if cap1[1638470] {
		t.Errorf("Table 1 should NOT have AddPath for EVPN")
	}

	// Test table 2 capability
	cap2 := p.GetAddPathCapability(table2Key)
	if cap2[65537] {
		t.Errorf("Table 2 should NOT have AddPath for IPv4 Unicast")
	}
	if !cap2[1638470] {
		t.Errorf("Table 2 should have AddPath for EVPN")
	}

	// Verify tables are independent (can't compare maps directly, so check values)
	if cap1[65537] == cap2[65537] && cap1[1638470] == cap2[1638470] {
		// Both tables have same capabilities - would be wrong
		if cap1[65537] && cap1[1638470] {
			t.Errorf("Tables should have separate capability maps")
		}
	}
}

// TestMissingTable verifies GetAddPathCapability handles missing tables gracefully
func TestMissingTable(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	// Get capability for non-existent table
	cap := p.GetAddPathCapability("nonexistent-table")

	// Should return nil (not panic)
	if cap != nil {
		t.Errorf("Expected nil for missing table, got %v", cap)
	}

	// Accessing nil map should return false (Go zero value)
	if cap[65537] {
		t.Errorf("Nil map should return false for any key")
	}
}

// TestTableLifecycle verifies table properties are created and cleaned up properly
func TestTableLifecycle(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	tableKey := "10.0.0.10:0"

	// Initially table shouldn't exist
	cap := p.GetAddPathCapability(tableKey)
	if cap != nil {
		t.Errorf("Table should not exist initially")
	}

	// Simulate PeerUp - create table properties
	p.tableLock.Lock()
	p.tableProperties[tableKey] = PerTableProperties{
		addPathCapable: map[int]bool{
			65537: true,
		},
		tableInfoTLVs: []bmp.InformationalTLV{
			{
				InformationType: 3, // Table Name
				Information:     []byte("VRF-CUSTOMER-A"),
			},
		},
	}
	p.tableLock.Unlock()

	// Verify table exists
	cap = p.GetAddPathCapability(tableKey)
	if cap == nil {
		t.Errorf("Table should exist after PeerUp")
	}
	if !cap[65537] {
		t.Errorf("AddPath capability should be set")
	}

	// Verify table name
	tableName := p.GetTableName("10.0.0.1", "0:0")
	if tableName != "VRF-CUSTOMER-A" {
		t.Errorf("TableName = %v, want VRF-CUSTOMER-A", tableName)
	}

	// Simulate PeerDown - cleanup
	p.tableLock.Lock()
	delete(p.tableProperties, tableKey)
	p.tableLock.Unlock()

	// Verify table no longer exists
	cap = p.GetAddPathCapability(tableKey)
	if cap != nil {
		t.Errorf("Table should be deleted after PeerDown")
	}
}

// TestConcurrentTableAccess verifies thread safety
func TestConcurrentTableAccess(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	// Number of concurrent goroutines
	const numGoroutines = 10
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch goroutines that concurrently add/remove/read tables
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			tableKey := "10.0.0." + string(rune('0'+id)) + "0:0"

			for j := 0; j < numOperations; j++ {
				// Add table
				p.tableLock.Lock()
				p.tableProperties[tableKey] = PerTableProperties{
					addPathCapable: map[int]bool{65537: true},
				}
				p.tableLock.Unlock()

				// Read table
				cap := p.GetAddPathCapability(tableKey)
				if cap == nil {
					t.Errorf("Table should exist after creation")
				}

				// Remove table
				p.tableLock.Lock()
				delete(p.tableProperties, tableKey)
				p.tableLock.Unlock()

				// Read table again (should be nil)
				cap = p.GetAddPathCapability(tableKey)
				if cap != nil {
					t.Errorf("Table should be deleted")
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestGetTableName verifies table name extraction from TLVs
func TestGetTableName(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	tests := []struct {
		name      string
		bgpID     string
		rd        string
		tlvs      []bmp.InformationalTLV
		expected  string
	}{
		{
			name:  "Single table name TLV",
			bgpID: "10.0.0.1",
			rd:    "0:0",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-CUSTOMER-A")},
			},
			expected: "VRF-CUSTOMER-A",
		},
		{
			name:  "Multiple TLVs including table name",
			bgpID: "192.168.1.1",
			rd:    "65000:100",
			tlvs: []bmp.InformationalTLV{
				{InformationType: 1, Information: []byte("String TLV")},
				{InformationType: 3, Information: []byte("VRF-INTERNET")},
				{InformationType: 2, Information: []byte("SysDescr")},
			},
			expected: "VRF-INTERNET",
		},
		{
			name:     "No table name TLV",
			bgpID:    "10.0.0.1",
			rd:       "0:0",
			tlvs:     []bmp.InformationalTLV{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tableKey := tt.bgpID + tt.rd

			p.tableLock.Lock()
			p.tableProperties[tableKey] = PerTableProperties{
				addPathCapable: make(map[int]bool),
				tableInfoTLVs:  tt.tlvs,
			}
			p.tableLock.Unlock()

			got := p.GetTableName(tt.bgpID, tt.rd)
			if got != tt.expected {
				t.Errorf("GetTableName() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Note: mockPublisher already defined in bmpstats_test.go, reusing it
