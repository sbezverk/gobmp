package validator

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/kafka"
	bmp_message "github.com/sbezverk/gobmp/pkg/message"
)

// buildMsgBytes encodes a sequence of StoredMessages into a byte slice.
func buildMsgBytes(records ...StoredMessage) []byte {
	var out []byte
	for _, r := range records {
		out = append(out, r.Marshal()...)
	}
	return out
}

// --- buildMessagesMap ---

func TestBuildMessagesMap_Empty(t *testing.T) {
	m, err := buildMessagesMap([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}

func TestBuildMessagesMap_SingleMessage(t *testing.T) {
	payload := []byte(`{"prefix":"10.0.0.0"}`)
	data := buildMsgBytes(StoredMessage{TopicType: bmp.UnicastPrefixV4Msg, Len: uint32(len(payload)), Message: payload})
	m, err := buildMessagesMap(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msgs, ok := m[bmp.UnicastPrefixV4Msg]
	if !ok {
		t.Fatalf("expected message type %d in map", bmp.UnicastPrefixV4Msg)
	}
	if len(msgs) != 1 {
		t.Errorf("expected 1 message, got %d", len(msgs))
	}
}

func TestBuildMessagesMap_MultipleTypes(t *testing.T) {
	p1 := []byte(`{"prefix":"10.0.0.0"}`)
	p2 := []byte(`{"prefix":"192.168.1.0"}`)
	data := buildMsgBytes(
		StoredMessage{TopicType: bmp.UnicastPrefixV4Msg, Len: uint32(len(p1)), Message: p1},
		StoredMessage{TopicType: bmp.UnicastPrefixMsg, Len: uint32(len(p2)), Message: p2},
	)
	m, err := buildMessagesMap(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("expected 2 type entries, got %d", len(m))
	}
}

func TestBuildMessagesMap_SameTypeTwoMessages(t *testing.T) {
	p1 := []byte(`{"prefix":"10.0.0.1"}`)
	p2 := []byte(`{"prefix":"10.0.0.2"}`)
	data := buildMsgBytes(
		StoredMessage{TopicType: bmp.UnicastPrefixV4Msg, Len: uint32(len(p1)), Message: p1},
		StoredMessage{TopicType: bmp.UnicastPrefixV4Msg, Len: uint32(len(p2)), Message: p2},
	)
	m, err := buildMessagesMap(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m[bmp.UnicastPrefixV4Msg]) != 2 {
		t.Errorf("expected 2 messages for type %d, got %d", bmp.UnicastPrefixV4Msg, len(m[bmp.UnicastPrefixV4Msg]))
	}
}

func TestBuildMessagesMap_TruncatedHeader(t *testing.T) {
	_, err := buildMessagesMap([]byte{0x00, 0x00, 0x00}) // only 3 bytes, need at least 8
	if err == nil {
		t.Error("expected error for truncated header, got nil")
	}
}

func TestBuildMessagesMap_InvalidTypeTooHigh(t *testing.T) {
	b := make([]byte, 8)
	invalidType := uint32(bmp.BMPRawMsg) + 1 // type greater than the maximum allowed BMP message type
	binary.BigEndian.PutUint32(b[:4], invalidType)
	binary.BigEndian.PutUint32(b[4:8], 0)
	_, err := buildMessagesMap(b)
	if err == nil {
		t.Error("expected error for message type > ", bmp.BMPRawMsg, ", got nil")
	}
}

func TestBuildMessagesMap_CorruptedLength(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[:4], bmp.UnicastPrefixV4Msg)
	binary.BigEndian.PutUint32(b[4:8], 9999) // claims 9999 bytes but buffer has none
	_, err := buildMessagesMap(b)
	if err == nil {
		t.Error("expected error for corrupted length field, got nil")
	}
}

// --- makeUnicastPrefixKey ---

func TestMakeUnicastPrefixKey_Nil(t *testing.T) {
	_, err := makeUnicastPrefixKey(nil)
	if err == nil {
		t.Error("expected error for nil input, got nil")
	}
}

func TestMakeUnicastPrefixKey_Valid(t *testing.T) {
	u := &bmp_message.UnicastPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 24,
		PeerIP:    "192.168.1.1",
		Nexthop:   "10.1.1.1",
	}
	key, err := makeUnicastPrefixKey(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "10.0.0.0_24_192.168.1.1_10.1.1.1"
	if key != want {
		t.Errorf("key = %q, want %q", key, want)
	}
}

// --- Store ---

func TestStore_NilFile(t *testing.T) {
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Store([]*kafka.TopicDescriptor{}, nil, stopCh, errCh)
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected non-nil error for nil file, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Store to return on nil file")
	}
}

func TestStore_StopCh_Returns(t *testing.T) {
	f, err := os.CreateTemp("", "store_stop_test_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()
	defer func() {
		_ = f.Close()
	}()

	stopCh := make(chan struct{})
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		Store([]*kafka.TopicDescriptor{}, f, stopCh, errCh)
		close(done)
	}()

	close(stopCh)
	select {
	case <-done:
		// Store returned as expected after stopCh was closed
	case <-time.After(2 * time.Second):
		t.Fatal("Store did not return after stopCh was closed")
	}
}

func TestStore_WritesUnicastMessage(t *testing.T) {
	f, err := os.CreateTemp("", "store_write_test_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()
	defer func() {
		_ = f.Close()
	}()

	u := &bmp_message.UnicastPrefix{
		Prefix:    "172.16.0.0",
		PrefixLen: 16,
		PeerIP:    "10.0.0.1",
		Nexthop:   "10.0.0.2",
	}
	msgJSON, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}

	topicChan := make(chan []byte, 1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicName: "test.unicast.v4",
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		Store(topics, f, stopCh, errCh)
		close(done)
	}()

	topicChan <- msgJSON
	// Give the worker + manager time to process and write the message.
	deadline := time.Now().Add(2 * time.Second)
	for {
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for Store to write message")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Store did not return after stopCh was closed")
	}

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("expected file to have content after message was stored, but it is empty")
	}
}

func TestStore_SkipsEORMessage(t *testing.T) {
	f, err := os.CreateTemp("", "store_eor_test_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Remove(f.Name())
	}()
	defer func() {
		_ = f.Close()
	}()

	topicChan := make(chan []byte, 1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicName: "test.unicast.v4",
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		Store(topics, f, stopCh, errCh)
		close(done)
	}()

	eor := &bmp_message.UnicastPrefix{IsEOR: true}
	eorJSON, _ := json.Marshal(eor)
	topicChan <- eorJSON
	waitDeadline := time.Now().Add(1 * time.Second)
	for len(topicChan) != 0 {
		if time.Now().After(waitDeadline) {
			t.Fatal("timed out waiting for EOR message to be consumed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Store did not return after stopCh was closed")
	}

	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Errorf("expected empty file after EOR-only message, got %d bytes", info.Size())
	}
}

// --- Check ---

func TestCheck_NoTestMessagesForTopic(t *testing.T) {
	// Stored bytes contain type V4 but the topic requests type V6.
	payload := []byte(`{"prefix":"1.2.3.0","prefix_len":24,"peer_ip":"10.0.0.1","nexthop":"10.0.0.2"}`)
	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(payload)),
		Message:   payload,
	}).Marshal()

	topicChan := make(chan []byte, 1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicName: "test.unicast.v6",
			TopicType: bmp.UnicastPrefixV6Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected error when no test messages for topic type, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Check to return error")
	}
}

func TestCheck_MatchingMessages(t *testing.T) {
	u := &bmp_message.UnicastPrefix{
		Prefix:    "192.0.2.0",
		PrefixLen: 24,
		PeerIP:    "10.1.1.1",
		Nexthop:   "10.1.1.2",
	}
	msgJSON, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}

	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(msgJSON)),
		Message:   msgJSON,
	}).Marshal()

	topicChan := make(chan []byte, 1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicName: "test.unicast.v4",
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	topicChan <- msgJSON

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected success, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Check to complete")
	}
}

func TestCheck_KeyNotInDictionary(t *testing.T) {
	stored := &bmp_message.UnicastPrefix{
		Prefix:    "192.0.2.0",
		PrefixLen: 24,
		PeerIP:    "10.1.1.1",
		Nexthop:   "10.1.1.2",
	}
	storedJSON, _ := json.Marshal(stored)

	// Incoming message has a different Prefix so its key won't be in the dictionary.
	// The validator logs a warning and skips it rather than failing immediately,
	// so that transient/unexpected BGP messages (e.g. convergence withdrawals) don't
	// cause flaky test failures.
	incoming := &bmp_message.UnicastPrefix{
		Prefix:    "10.255.255.0",
		PrefixLen: 24,
		PeerIP:    "10.1.1.1",
		Nexthop:   "10.1.1.2",
	}
	incomingJSON, _ := json.Marshal(incoming)

	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(storedJSON)),
		Message:   storedJSON,
	}).Marshal()

	topicChan := make(chan []byte, 2)
	topics := []*kafka.TopicDescriptor{
		{
			TopicName: "test.unicast.v4",
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	// Send the unexpected message first — the validator logs a warning and skips it.
	topicChan <- incomingJSON

	// Then send the expected message so the validator can complete successfully.
	topicChan <- storedJSON

	select {
	case err := <-errCh:
		// A nil error means all dictionary entries were matched (Check only sends
		// nil when every worker's matched count reaches the dictionary size).
		// This simultaneously confirms: (a) the unexpected message was skipped with
		// a warning (not a hard failure), and (b) the expected message was verified.
		if err != nil {
			t.Errorf("unexpected error: unexpected messages should be skipped, not fail: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Check to complete")
	}
}

func TestCheck_EORMessagesSkippedInWorker(t *testing.T) {
	stored := &bmp_message.UnicastPrefix{
		Prefix:    "10.0.0.0",
		PrefixLen: 8,
		PeerIP:    "1.1.1.1",
		Nexthop:   "2.2.2.2",
	}
	storedJSON, _ := json.Marshal(stored)

	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(storedJSON)),
		Message:   storedJSON,
	}).Marshal()

	topicChan := make(chan []byte, 2)
	topics := []*kafka.TopicDescriptor{
		{
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	// Send EOR first — it must be skipped — then the real matching message.
	eor := &bmp_message.UnicastPrefix{IsEOR: true}
	eorJSON, _ := json.Marshal(eor)
	topicChan <- eorJSON
	topicChan <- storedJSON

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected success after EOR was skipped, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Check to complete")
	}
}

func TestCheck_StopCh(t *testing.T) {
	u := &bmp_message.UnicastPrefix{
		Prefix:    "192.0.2.0",
		PrefixLen: 24,
		PeerIP:    "10.1.1.1",
		Nexthop:   "10.1.1.2",
	}
	msgJSON, _ := json.Marshal(u)
	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(msgJSON)),
		Message:   msgJSON,
	}).Marshal()

	topicChan := make(chan []byte)
	topics := []*kafka.TopicDescriptor{
		{
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)

	done := make(chan struct{})
	go func() {
		Check(topics, storedBytes, stopCh, errCh)
		close(done)
	}()

	// Close before any message arrives; Check must return.
	close(stopCh)

	select {
	case <-done:
		// Check returned as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Check did not return after stopCh was closed")
	}
}

// staleMismatch builds a UnicastPrefix JSON message whose key matches
// expected but whose RouterIP field has a different value. This simulates
// the "stale" messages that arrive before BMP Initiation metadata is
// fully resolved in active-mode sessions.
func staleMismatch(expected *bmp_message.UnicastPrefix) []byte {
	stale := *expected // shallow copy — same key fields
	stale.RouterIP = "0.0.0.0"
	b, _ := json.Marshal(&stale)
	return b
}

// TestCheck_StaleMismatches_ThenMatch verifies that the worker tolerates
// fewer than maxStaleMismatches consecutive value-mismatches for the same
// key and still completes successfully when a correctly-matching message
// eventually arrives.
//
// The dictionary holds one entry. We send (maxStaleMismatches - 1) stale
// messages followed by the exact matching message. The worker must not
// fail during the stale window and must signal success on the final message.
func TestCheck_StaleMismatches_ThenMatch(t *testing.T) {
	expected := &bmp_message.UnicastPrefix{
		Action:    "add",
		Prefix:    "10.1.0.0",
		PrefixLen: 16,
		PeerIP:    "10.0.0.1",
		Nexthop:   "10.0.0.2",
		RouterIP:  "192.168.1.1",
	}
	expectedJSON, _ := json.Marshal(expected)

	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(expectedJSON)),
		Message:   expectedJSON,
	}).Marshal()

	topicChan := make(chan []byte, maxStaleMismatches+1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	// Send (maxStaleMismatches - 1) stale messages: same key, wrong RouterIP.
	// The budget has one slot remaining so the worker must not fail yet.
	for i := 0; i < maxStaleMismatches-1; i++ {
		topicChan <- staleMismatch(expected)
	}

	// Send the matching message. The worker must accept it and signal success.
	topicChan <- expectedJSON

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("expected success after stale window, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Check to complete")
	}
}

// TestCheck_StaleMismatches_BudgetExceeded verifies that the worker reports
// an error once the mismatch count for a key reaches maxStaleMismatches,
// even if a correct message has not yet arrived.
//
// We send exactly maxStaleMismatches stale messages for the same key. The
// worker must fail on the last one without waiting for a matching message.
func TestCheck_StaleMismatches_BudgetExceeded(t *testing.T) {
	expected := &bmp_message.UnicastPrefix{
		Action:    "add",
		Prefix:    "10.2.0.0",
		PrefixLen: 16,
		PeerIP:    "10.0.0.1",
		Nexthop:   "10.0.0.2",
		RouterIP:  "192.168.1.1",
	}
	expectedJSON, _ := json.Marshal(expected)

	storedBytes := (&StoredMessage{
		TopicType: bmp.UnicastPrefixV4Msg,
		Len:       uint32(len(expectedJSON)),
		Message:   expectedJSON,
	}).Marshal()

	topicChan := make(chan []byte, maxStaleMismatches+1)
	topics := []*kafka.TopicDescriptor{
		{
			TopicType: bmp.UnicastPrefixV4Msg,
			TopicChan: topicChan,
		},
	}
	stopCh := make(chan struct{})
	errCh := make(chan error, 1)
	go Check(topics, storedBytes, stopCh, errCh)

	// Send maxStaleMismatches stale messages. The budget is now exhausted and
	// the worker must report a non-nil error.
	for i := 0; i < maxStaleMismatches; i++ {
		topicChan <- staleMismatch(expected)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected error after mismatch budget was exceeded, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Check to report budget-exceeded error")
	}
}
