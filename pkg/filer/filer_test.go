package filer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestMsgOutJSONEncoding verifies that MsgOut with json.RawMessage produces valid JSON
func TestMsgOutJSONEncoding(t *testing.T) {
	tests := []struct {
		name     string
		msgType  int
		msgHash  string
		msgData  []byte
		wantErr  bool
	}{
		{
			name:    "simple unicast route",
			msgType: 1,
			msgHash: "abc123",
			msgData: []byte(`{"action":"add","prefix":"10.0.0.0/8"}`),
			wantErr: false,
		},
		{
			name:    "complex EVPN route with MAC",
			msgType: 2,
			msgHash: "def456",
			msgData: []byte(`{"action":"add","mac":"aa:bb:cc:dd:ee:ff","ip_address":"192.168.1.1"}`),
			wantErr: false,
		},
		{
			name:    "route with nested objects",
			msgType: 3,
			msgHash: "ghi789",
			msgData: []byte(`{"action":"add","base_attrs":{"as_path":[100,200,300]}}`),
			wantErr: false,
		},
		{
			name:    "route with special characters",
			msgType: 4,
			msgHash: "jkl012",
			msgData: []byte(`{"action":"add","description":"Test \"quoted\" value with\nnewline"}`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create MsgOut with json.RawMessage
			m := MsgOut{
				MsgType: tt.msgType,
				MsgHash: tt.msgHash,
				Msg:     json.RawMessage(tt.msgData),
			}

			// Marshal to JSON
			got, err := json.Marshal(&m)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			// Verify it's valid JSON by unmarshaling
			var result map[string]interface{}
			if err := json.Unmarshal(got, &result); err != nil {
				t.Fatalf("Output is not valid JSON: %v\nGot: %s", err, string(got))
			}

			// Verify msg_data is an object, not a string
			msgData, ok := result["msg_data"].(map[string]interface{})
			if !ok {
				t.Errorf("msg_data is not an object, got type: %T\nFull output: %s", result["msg_data"], string(got))
			}

			// Verify msg_data has expected action field
			if action, ok := msgData["action"].(string); !ok || action != "add" {
				t.Errorf("msg_data.action = %v, want 'add'", msgData["action"])
			}

			// Verify msg_type matches
			if msgType, ok := result["msg_type"].(float64); !ok || int(msgType) != tt.msgType {
				t.Errorf("msg_type = %v, want %d", result["msg_type"], tt.msgType)
			}

			// Verify msg_hash matches
			if msgHash, ok := result["msg_hash"].(string); !ok || msgHash != tt.msgHash {
				t.Errorf("msg_hash = %v, want %s", result["msg_hash"], tt.msgHash)
			}
		})
	}
}

// TestPublishMessageValidJSON tests end-to-end file writing and JSON validity
func TestPublishMessageValidJSON(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.json")

	// Create filer
	pub, err := NewFiler(tmpFile)
	if err != nil {
		t.Fatalf("NewFiler failed: %v", err)
	}
	defer pub.Stop()

	// Publish a message
	msgData := []byte(`{"action":"add","prefix":"192.168.0.0/16","peer_ip":"10.0.0.1"}`)
	err = pub.PublishMessage(1, []byte("testhash"), msgData)
	if err != nil {
		t.Fatalf("PublishMessage failed: %v", err)
	}

	// Close file to flush
	pub.Stop()

	// Read file and verify JSON is valid
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Remove trailing newline for parsing
	if len(content) == 0 {
		t.Fatal("File is empty")
	}
	line := content[:len(content)-1]

	// Verify it's valid JSON
	if !json.Valid(line) {
		t.Errorf("Output is not valid JSON:\n%s", string(line))
	}

	// Parse outer JSON
	var outer map[string]interface{}
	if err := json.Unmarshal(line, &outer); err != nil {
		t.Fatalf("Outer JSON invalid: %v\nContent: %s", err, string(line))
	}

	// Verify msg_data is object, not string
	msgDataVal, ok := outer["msg_data"].(map[string]interface{})
	if !ok {
		t.Fatalf("msg_data is not an object, got type: %T\nContent: %s", outer["msg_data"], string(line))
	}

	// Verify msg_data content
	if action, ok := msgDataVal["action"].(string); !ok || action != "add" {
		t.Errorf("msg_data.action = %v, want 'add'", msgDataVal["action"])
	}
	if prefix, ok := msgDataVal["prefix"].(string); !ok || prefix != "192.168.0.0/16" {
		t.Errorf("msg_data.prefix = %v, want '192.168.0.0/16'", msgDataVal["prefix"])
	}
	if peerIP, ok := msgDataVal["peer_ip"].(string); !ok || peerIP != "10.0.0.1" {
		t.Errorf("msg_data.peer_ip = %v, want '10.0.0.1'", msgDataVal["peer_ip"])
	}
}

// TestPublishMessageMultiple tests that multiple messages create valid newline-delimited JSON
func TestPublishMessageMultiple(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-multiple.json")

	// Create filer
	pub, err := NewFiler(tmpFile)
	if err != nil {
		t.Fatalf("NewFiler failed: %v", err)
	}
	defer pub.Stop()

	// Publish multiple messages
	messages := []struct {
		msgType int
		msgHash string
		msgData string
	}{
		{1, "hash1", `{"action":"add","prefix":"10.1.0.0/16"}`},
		{2, "hash2", `{"action":"add","prefix":"10.2.0.0/16"}`},
		{3, "hash3", `{"action":"delete","prefix":"10.3.0.0/16"}`},
	}

	for _, msg := range messages {
		err := pub.PublishMessage(msg.msgType, []byte(msg.msgHash), []byte(msg.msgData))
		if err != nil {
			t.Fatalf("PublishMessage failed for %s: %v", msg.msgHash, err)
		}
	}

	// Close file to flush
	pub.Stop()

	// Read file
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Split by newlines and verify each line
	start := 0
	lineNum := 0
	for i, b := range content {
		if b == '\n' {
			line := content[start:i]
			if len(line) > 0 {
				lineNum++
				// Verify each line is valid JSON
				if !json.Valid(line) {
					t.Errorf("Line %d is not valid JSON: %s", lineNum, string(line))
				}
				// Parse and verify it's an object with msg_data
				var obj map[string]interface{}
				if err := json.Unmarshal(line, &obj); err != nil {
					t.Errorf("Line %d failed to unmarshal: %v", lineNum, err)
				} else {
					// Verify msg_data is object, not string
					if _, ok := obj["msg_data"].(map[string]interface{}); !ok {
						t.Errorf("Line %d: msg_data is not an object: %T", lineNum, obj["msg_data"])
					}
				}
			}
			start = i + 1
		}
	}

	// Verify we got expected number of lines
	if lineNum != len(messages) {
		t.Errorf("Expected %d lines, got %d", len(messages), lineNum)
	}
}

// TestNoDoubleEscaping verifies that json.RawMessage prevents double-escaping
func TestNoDoubleEscaping(t *testing.T) {
	m := MsgOut{
		MsgType: 1,
		MsgHash: "test",
		Msg:     json.RawMessage(`{"action":"add","community":"64512:100"}`),
	}

	got, err := json.Marshal(&m)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// The output should NOT contain escaped quotes inside msg_data
	// It should be: {"msg_data":{"action":"add",...}}
	// NOT: {"msg_data":"{\"action\":\"add\",...}"}

	str := string(got)

	// Should NOT find escaped quotes after msg_data:
	if contains(str, `"msg_data":"{\"action\"`) {
		t.Errorf("Found double-escaped JSON (string instead of object):\n%s", str)
	}

	// Should find unescaped structure:
	if !contains(str, `"msg_data":{"action":"add"`) {
		t.Errorf("Expected nested JSON object in msg_data, got:\n%s", str)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr)))
}
