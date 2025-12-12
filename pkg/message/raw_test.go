package message

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"strings"
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

// TestProduceRawMessage tests RAW message production
func TestProduceRawMessage(t *testing.T) {
	adminID := "test-collector"
	hash := md5.Sum([]byte(adminID))
	expectedAdminHash := hex.EncodeToString(hash[:])

	// Create test peer header with properly initialized fields
	peerHeader := &bmp.PerPeerHeader{
		PeerAS:            65001,
		PeerAddress:       []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1}, // IPv4-mapped IPv6: ::ffff:192.168.1.1
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
		publisher: mockPub,
		adminHash: expectedAdminHash,
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

	// Verify message content
	output := string(mockPub.lastMessage)

	// Check header fields
	expectedFields := map[string]string{
		"V: 1.7":     "",
		"C_HASH_ID:": expectedAdminHash,
		"R_HASH:":    peerHeader.GetPeerHash(),
		"R_IP:":      peerHeader.GetPeerAddrString(),
		"L:":         "10",
	}

	for field, expectedValue := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("Output missing field: %s", field)
		}
		if expectedValue != "" && !strings.Contains(output, expectedValue) {
			t.Errorf("Output missing value %s for field %s", expectedValue, field)
		}
	}

	// Verify raw message is appended after header
	headerEnd := strings.Index(output, "\n\n")
	if headerEnd == -1 {
		t.Error("Header not properly terminated with double newline")
	}

	messageStart := headerEnd + 2
	if !bytes.Equal(mockPub.lastMessage[messageStart:], rawData) {
		t.Error("Raw message data does not match expected")
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

	// Verify length is 0
	output := string(mockPub.lastMessage)
	if !strings.Contains(output, "L: 0") {
		t.Error("Length field should be 0 for empty message")
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
}
