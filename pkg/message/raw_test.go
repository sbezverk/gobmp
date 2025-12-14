package message

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// mockPublisherRAW implements pub.Publisher interface for RAW message testing
type mockPublisherRAW struct {
	lastMessage     []byte
	lastMessageType int
	publishCalled   bool
}

func (m *mockPublisherRAW) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m.publishCalled = true
	m.lastMessageType = msgType
	m.lastMessage = make([]byte, len(msg))
	copy(m.lastMessage, msg)
	return nil
}

func (m *mockPublisherRAW) Stop() {}

// TestProduceRawMessage tests RAW message production with binary format
func TestProduceRawMessage(t *testing.T) {
	adminID := "test-collector"
	collectorHash := md5.Sum([]byte(adminID))
	adminHash := hex.EncodeToString(collectorHash[:])

	// Create test peer header with properly initialized fields
	peerHeader := &bmp.PerPeerHeader{
		PeerAS:            65001,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1}, // IPv4
		PeerBGPID:         []byte{192, 168, 1, 1},
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}

	// Create RAW message
	rawData := []byte{0x03, 0x00, 0x00, 0x00, 0x0A, 0x01, 0xAA, 0xBB, 0xCC, 0xDD}
	rawMsg := &bmp.RawMessage{
		Msg: rawData,
	}

	// Create producer with mock publisher
	mockPub := &mockPublisherRAW{}
	p := &producer{
		publisher:        mockPub,
		adminHash:        adminHash,
		collectorAdminID: adminID,
	}

	// Produce message
	msg := bmp.Message{
		PeerHeader: peerHeader,
		Payload:    rawMsg,
	}
	p.produceRawMessage(msg)

	// Verify publish was called
	if !mockPub.publishCalled {
		t.Error("PublishMessage was not called")
	}

	// Verify message type
	if mockPub.lastMessageType != bmp.BMPRawMsg {
		t.Errorf("Message type = %d, want %d", mockPub.lastMessageType, bmp.BMPRawMsg)
	}

	// Parse and verify binary header format
	output := mockPub.lastMessage
	if len(output) < 78 {
		t.Fatalf("Message too short: got %d bytes, want at least 78", len(output))
	}

	// Offset 0: Magic Number (4 bytes) = 0x4F424D50 ("OBMP")
	magicNumber := binary.BigEndian.Uint32(output[0:4])
	if magicNumber != 0x4F424D50 {
		t.Errorf("Magic number = 0x%X, want 0x4F424D50", magicNumber)
	}

	// Offset 4: Version Major (1 byte) = 1
	if output[4] != 1 {
		t.Errorf("Version major = %d, want 1", output[4])
	}

	// Offset 5: Version Minor (1 byte) = 7
	if output[5] != 7 {
		t.Errorf("Version minor = %d, want 7", output[5])
	}

	// Offset 6: Header Length (2 bytes)
	headerLen := binary.BigEndian.Uint16(output[6:8])
	expectedHeaderLen := uint16(78 + len(adminID)) // 78 + N (router group is empty)
	if headerLen != expectedHeaderLen {
		t.Errorf("Header length = %d, want %d", headerLen, expectedHeaderLen)
	}

	// Offset 8: BMP Message Length (4 bytes)
	bmpMsgLen := binary.BigEndian.Uint32(output[8:12])
	if bmpMsgLen != uint32(len(rawData)) {
		t.Errorf("BMP message length = %d, want %d", bmpMsgLen, len(rawData))
	}

	// Offset 12: Flags (1 byte) - IPv4 router = 0x80
	flags := output[12]
	if flags != 0x80 {
		t.Errorf("Flags = 0x%X, want 0x80", flags)
	}

	// Offset 13: Message Type (1 byte) = 12 (BMP_RAW)
	msgType := output[13]
	if msgType != 12 {
		t.Errorf("Message type = %d, want 12", msgType)
	}

	// Offset 22: Collector Hash (16 bytes)
	if !bytes.Equal(output[22:38], collectorHash[:]) {
		t.Error("Collector hash does not match")
	}

	// Offset 38: Collector Admin ID Length (2 bytes)
	adminIDLen := binary.BigEndian.Uint16(output[38:40])
	if adminIDLen != uint16(len(adminID)) {
		t.Errorf("Collector admin ID length = %d, want %d", adminIDLen, len(adminID))
	}

	// Offset 40: Collector Admin ID
	collectorAdminID := string(output[40 : 40+adminIDLen])
	if collectorAdminID != adminID {
		t.Errorf("Collector admin ID = %s, want %s", collectorAdminID, adminID)
	}

	// Calculate router hash
	routerIPStr := peerHeader.GetPeerAddrString()
	expectedRouterHash := md5.Sum([]byte(routerIPStr))

	// Offset 40+N: Router Hash (16 bytes)
	routerHashOffset := 40 + len(adminID)
	if !bytes.Equal(output[routerHashOffset:routerHashOffset+16], expectedRouterHash[:]) {
		t.Error("Router hash does not match")
	}

	// Offset 56+N: Router IP (16 bytes)
	routerIPOffset := routerHashOffset + 16
	expectedRouterIP, _ := encodeIPToBytes(routerIPStr)
	if !bytes.Equal(output[routerIPOffset:routerIPOffset+16], expectedRouterIP[:]) {
		t.Error("Router IP does not match")
	}

	// Offset 72+N: Router Group Length (2 bytes) = 0
	routerGroupLenOffset := routerIPOffset + 16
	routerGroupLen := binary.BigEndian.Uint16(output[routerGroupLenOffset : routerGroupLenOffset+2])
	if routerGroupLen != 0 {
		t.Errorf("Router group length = %d, want 0", routerGroupLen)
	}

	// Offset 74+N: Row Count (4 bytes) = 1
	rowCountOffset := routerGroupLenOffset + 2
	rowCount := binary.BigEndian.Uint32(output[rowCountOffset : rowCountOffset+4])
	if rowCount != 1 {
		t.Errorf("Row count = %d, want 1", rowCount)
	}

	// Verify raw BMP message is appended after header
	bmpMsgOffset := rowCountOffset + 4
	if !bytes.Equal(output[bmpMsgOffset:], rawData) {
		t.Error("Raw BMP message data does not match expected")
	}
}

// TestProduceRawMessage_NilPeerHeader tests error handling for nil peer header
func TestProduceRawMessage_NilPeerHeader(t *testing.T) {
	mockPub := &mockPublisherRAW{}
	p := &producer{
		publisher: mockPub,
		adminHash: "test-hash",
	}

	rawMsg := &bmp.RawMessage{
		Msg: []byte{0x01, 0x02, 0x03},
	}

	msg := bmp.Message{
		PeerHeader: nil, // Nil peer header should cause error
		Payload:    rawMsg,
	}

	p.produceRawMessage(msg)

	// Should not publish if peer header is nil
	if mockPub.publishCalled {
		t.Error("PublishMessage should not be called with nil peer header")
	}
}

// TestProduceRawMessage_InvalidPayload tests error handling for invalid payload
func TestProduceRawMessage_InvalidPayload(t *testing.T) {
	mockPub := &mockPublisherRAW{}
	p := &producer{
		publisher: mockPub,
		adminHash: "test-hash",
	}

	peerHeader := &bmp.PerPeerHeader{
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}

	msg := bmp.Message{
		PeerHeader: peerHeader,
		Payload:    &bmp.StatsReport{}, // Wrong payload type
	}

	p.produceRawMessage(msg)

	// Should not publish if payload is wrong type
	if mockPub.publishCalled {
		t.Error("PublishMessage should not be called with invalid payload type")
	}
}

// TestProduceRawMessage_EmptyMessage tests with empty raw message
func TestProduceRawMessage_EmptyMessage(t *testing.T) {
	adminID := "test-admin"
	mockPub := &mockPublisherRAW{}
	p := &producer{
		publisher:        mockPub,
		adminHash:        "test-hash",
		collectorAdminID: adminID,
	}

	peerHeader := &bmp.PerPeerHeader{
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         make([]byte, 4),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}
	rawMsg := &bmp.RawMessage{
		Msg: []byte{}, // Empty message
	}

	msg := bmp.Message{
		PeerHeader: peerHeader,
		Payload:    rawMsg,
	}

	p.produceRawMessage(msg)

	// Should publish even with empty message
	if !mockPub.publishCalled {
		t.Error("PublishMessage should be called even with empty message")
	}

	// Verify BMP message length is 0 in binary header
	output := mockPub.lastMessage
	bmpMsgLen := binary.BigEndian.Uint32(output[8:12])
	if bmpMsgLen != 0 {
		t.Errorf("BMP message length = %d, want 0", bmpMsgLen)
	}
}

// TestSetConfig tests producer configuration
func TestSetConfig(t *testing.T) {
	p := &producer{}

	// Test with nil config
	err := p.SetConfig(nil)
	if err != nil {
		t.Errorf("SetConfig(nil) should not error, got: %v", err)
	}

	// Test with valid config
	config := &Config{
		AdminID: "test-admin",
	}

	err = p.SetConfig(config)
	if err != nil {
		t.Errorf("SetConfig() error = %v", err)
	}

	// Verify collector admin ID was set
	if p.collectorAdminID != "test-admin" {
		t.Errorf("collectorAdminID = %s, want test-admin", p.collectorAdminID)
	}

	// Verify hash was set
	if p.adminHash == "" {
		t.Error("adminHash should be set after SetConfig")
	}

	// Verify hash is MD5 of admin ID
	expectedHash := md5.Sum([]byte("test-admin"))
	expectedHashStr := hex.EncodeToString(expectedHash[:])
	if p.adminHash != expectedHashStr {
		t.Errorf("adminHash = %s, want %s", p.adminHash, expectedHashStr)
	}
}

// TestSetConfig_EmptyAdminID tests with empty admin ID
func TestSetConfig_EmptyAdminID(t *testing.T) {
	p := &producer{}

	config := &Config{
		AdminID: "",
	}

	err := p.SetConfig(config)
	if err != nil {
		t.Errorf("SetConfig() error = %v", err)
	}

	// adminHash should remain empty
	if p.adminHash != "" {
		t.Error("adminHash should remain empty when AdminID is empty")
	}

	// collectorAdminID should remain empty
	if p.collectorAdminID != "" {
		t.Error("collectorAdminID should remain empty when AdminID is empty")
	}
}

// TestHelperFunctions tests binary header helper functions
func TestCalculateHeaderLength(t *testing.T) {
	tests := []struct {
		name             string
		collectorAdminID string
		routerGroup      string
		expectedLen      uint16
	}{
		{"Both empty", "", "", 78},
		{"Collector only", "test-collector", "", 78 + 14}, // "test-collector" is 14 chars
		{"Router group only", "", "test-group", 78 + 10},
		{"Both present", "collector", "group", 78 + 9 + 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateHeaderLength(tt.collectorAdminID, tt.routerGroup)
			if result != tt.expectedLen {
				t.Errorf("calculateHeaderLength() = %d, want %d", result, tt.expectedLen)
			}
		})
	}
}

func TestEncodeIPToBytes(t *testing.T) {
	tests := []struct {
		name        string
		ip          string
		expectError bool
	}{
		{"Valid IPv4", "192.168.1.1", false},
		{"Valid IPv6", "2001:db8::1", false},
		{"Invalid IP", "not-an-ip", true},
		{"Empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encodeIPToBytes(tt.ip)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Verify result is not zero array
				var zero [16]byte
				if result == zero && tt.ip != "" {
					t.Error("Result should not be zero array for valid IP")
				}
			}
		})
	}
}

func TestIsIPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv4", "192.168.1.1", false},
		{"IPv6", "2001:db8::1", true},
		{"IPv4-mapped IPv6", "::ffff:192.168.1.1", false},
		{"Invalid IP", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPv6(tt.ip)
			if result != tt.expected {
				t.Errorf("isIPv6(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestCalculateFlags(t *testing.T) {
	tests := []struct {
		name     string
		isIPv6   bool
		expected uint8
	}{
		{"IPv4", false, 0x80},
		{"IPv6", true, 0xC0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateFlags(tt.isIPv6)
			if result != tt.expected {
				t.Errorf("calculateFlags(%v) = 0x%X, want 0x%X", tt.isIPv6, result, tt.expected)
			}
		})
	}
}

func TestGenerateMD5Hash(t *testing.T) {
	input := []byte("test-input")
	result := generateMD5Hash(input)

	// Verify it's MD5 by comparing with crypto/md5
	expected := md5.Sum(input)
	if result != expected {
		t.Error("generateMD5Hash result does not match expected MD5")
	}

	// Verify it's 16 bytes
	if len(result) != 16 {
		t.Errorf("MD5 hash length = %d, want 16", len(result))
	}
}

func TestGetCurrentTimestamp(t *testing.T) {
	sec, usec := getCurrentTimestamp()

	// Verify seconds is reasonable (after 2020)
	if sec < 1577836800 { // Jan 1, 2020
		t.Errorf("Timestamp seconds = %d, seems too old", sec)
	}

	// Verify microseconds is within valid range
	if usec >= 1000000 {
		t.Errorf("Timestamp microseconds = %d, should be < 1000000", usec)
	}
}

// TestHeaderWriter tests the error accumulator pattern
func TestHeaderWriter(t *testing.T) {
	t.Run("Successful writes", func(t *testing.T) {
		w := &headerWriter{}
		w.write(uint32(0x4F424D50))
		w.write(uint8(1))
		w.write(uint16(100))
		w.writeBytes([]byte{0xAA, 0xBB})
		w.writeString("test")

		if w.err != nil {
			t.Errorf("Unexpected error: %v", w.err)
		}

		// Verify buffer has expected size
		expected := 4 + 1 + 2 + 2 + 4 // uint32 + uint8 + uint16 + 2 bytes + "test"
		if w.buf.Len() != expected {
			t.Errorf("Buffer length = %d, want %d", w.buf.Len(), expected)
		}
	})

	t.Run("Error stops subsequent writes", func(t *testing.T) {
		w := &headerWriter{}
		w.write(uint32(123))

		// Simulate an error
		w.err = fmt.Errorf("simulated error")

		initialLen := w.buf.Len()

		// These writes should not happen
		w.write(uint32(456))
		w.writeBytes([]byte{0xFF})

		// Buffer should not have grown
		if w.buf.Len() != initialLen {
			t.Errorf("Buffer grew after error, len = %d, want %d", w.buf.Len(), initialLen)
		}
	})
}
