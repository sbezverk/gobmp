package parser

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// buildPeerDownMsg returns a complete BMP PeerDown message as a byte slice.
// perPeerHeader must be exactly 42 bytes (bmp.PerPeerHeaderLength).
func buildPeerDownMsg(perPeerHeader []byte, reason byte, extraData []byte) []byte {
	body := append([]byte{reason}, extraData...)
	msgLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength + len(body)
	b := make([]byte, msgLen)
	b[0] = 3 // BMP version
	binary.BigEndian.PutUint32(b[1:5], uint32(msgLen))
	b[5] = bmp.PeerDownMsg
	copy(b[6:], perPeerHeader)
	copy(b[6+bmp.PerPeerHeaderLength:], body)
	return b
}

// buildStatsReportMsg returns a BMP StatsReport message with one TLV
// (type=1, length=4, value=tlvValue).
func buildStatsReportMsg(perPeerHeader []byte, tlvValue uint32) []byte {
	statsBody := make([]byte, 4+4+4)
	binary.BigEndian.PutUint32(statsBody[0:], 1) // count=1
	binary.BigEndian.PutUint16(statsBody[4:], 1) // TLV type=1
	binary.BigEndian.PutUint16(statsBody[6:], 4) // TLV length=4
	binary.BigEndian.PutUint32(statsBody[8:], tlvValue)
	msgLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength + len(statsBody)
	b := make([]byte, msgLen)
	b[0] = 3
	binary.BigEndian.PutUint32(b[1:5], uint32(msgLen))
	b[5] = bmp.StatsReportMsg
	copy(b[6:], perPeerHeader)
	copy(b[6+bmp.PerPeerHeaderLength:], statsBody)
	return b
}

// buildInitiationMsg returns a minimal (empty-body) BMP Initiation message.
func buildInitiationMsg() []byte {
	b := make([]byte, bmp.CommonHeaderLength)
	b[0] = 3
	binary.BigEndian.PutUint32(b[1:5], uint32(bmp.CommonHeaderLength))
	b[5] = bmp.InitiationMsg
	return b
}

// collectMessages drains the producer queue and returns all collected messages.
// parsingWorker is called synchronously in tests, so all sends have completed
// before this is called. We do not close the channel because it is
// producer-owned (parsingWorker sends on it).
func collectMessages(q chan bmp.Message) []bmp.Message {
	var msgs []bmp.Message
	for len(q) > 0 {
		msgs = append(msgs, <-q)
	}
	return msgs
}

// TestParsingWorkerConsecutivePeerDown verifies that two PeerDown messages in one
// buffer both produce output. This catches the double-advance bug where
// pos was incremented by PerPeerHeaderLength inside the switch AND again by
// (MessageLength-CommonHeaderLength) after the switch, causing the cursor to
// overshoot by 42 bytes and land in the middle of the second message.
func TestParsingWorkerConsecutivePeerDown(t *testing.T) {
	emptyPPH := make([]byte, bmp.PerPeerHeaderLength)
	input := append(buildPeerDownMsg(emptyPPH, 5, nil), // reason 5
		buildPeerDownMsg(emptyPPH, 1, nil)...) // reason 1

	producerQueue := make(chan bmp.Message, 10)
	p := &parser{producerQueue: producerQueue, config: &Config{}}
	p.parsingWorker(input)
	msgs := collectMessages(producerQueue)

	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d — double-advance bug likely not fixed", len(msgs))
	}
	for i, want := range []uint8{5, 1} {
		pd, ok := msgs[i].Payload.(*bmp.PeerDownMessage)
		if !ok {
			t.Fatalf("msgs[%d] payload type = %T, want *bmp.PeerDownMessage", i, msgs[i].Payload)
		}
		if pd.Reason != want {
			t.Errorf("msgs[%d] reason = %d, want %d", i, pd.Reason, want)
		}
	}
}

// TestParsingWorkerUnknownPeerTypeSkipped verifies that a peer-bearing message
// with an unknown peer type byte (0xFF) is skipped rather than aborting the
// worker, and that a valid message following it is still processed.
func TestParsingWorkerUnknownPeerTypeSkipped(t *testing.T) {
	// Build a PeerDown with an unknown peer type byte (0xFF in byte 0 of PPH).
	unknownPPH := make([]byte, bmp.PerPeerHeaderLength)
	unknownPPH[0] = 0xFF // unrecognized peer type
	invalidMsg := buildPeerDownMsg(unknownPPH, 1, nil)

	// Follow it with a valid PeerDown.
	validPPH := make([]byte, bmp.PerPeerHeaderLength)
	validMsg := buildPeerDownMsg(validPPH, 5, nil)

	input := append(invalidMsg, validMsg...)
	producerQueue := make(chan bmp.Message, 10)
	p := &parser{producerQueue: producerQueue, config: &Config{}}
	p.parsingWorker(input)
	msgs := collectMessages(producerQueue)

	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (valid PeerDown), got %d — unknown peer type not skipped cleanly", len(msgs))
	}
	pd, ok := msgs[0].Payload.(*bmp.PeerDownMessage)
	if !ok {
		t.Fatalf("payload type = %T, want *bmp.PeerDownMessage", msgs[0].Payload)
	}
	if pd.Reason != 5 {
		t.Errorf("reason = %d, want 5", pd.Reason)
	}
}

// TestParsingWorkerStatsReportBoundedSlice verifies the StatsReport payload slice
// is bounded to the current message. The old code used an open-ended slice
// b[pos+PerPeerHeaderLength:] which included bytes from the following message;
// if those bytes caused a TLV length overflow the stats message was lost entirely.
func TestParsingWorkerStatsReportBoundedSlice(t *testing.T) {
	emptyPPH := make([]byte, bmp.PerPeerHeaderLength)
	input := append(buildStatsReportMsg(emptyPPH, 42), buildInitiationMsg()...)

	producerQueue := make(chan bmp.Message, 10)
	p := &parser{producerQueue: producerQueue, config: &Config{}}
	p.parsingWorker(input)
	msgs := collectMessages(producerQueue)

	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (StatsReport), got %d — bounded slice bug likely not fixed", len(msgs))
	}
	sr, ok := msgs[0].Payload.(*bmp.StatsReport)
	if !ok {
		t.Fatalf("payload type = %T, want *bmp.StatsReport", msgs[0].Payload)
	}
	if sr.StatsCount != 1 {
		t.Errorf("StatsCount = %d, want 1", sr.StatsCount)
	}
	if len(sr.StatsTLV) != 1 || sr.StatsTLV[0].InformationType != 1 {
		t.Errorf("unexpected StatsTLV: %+v", sr.StatsTLV)
	}
}

// TestParsingWorkerShortMessageLength verifies that a peer-bearing message whose
// MessageLength is too small to contain a Per-Peer Header is rejected cleanly
// (logged and worker returns) rather than panicking via an inverted or
// out-of-bounds slice expression.
func TestParsingWorkerShortMessageLength(t *testing.T) {
	tests := []struct {
		name    string
		msgType byte
	}{
		{"RouteMonitor too short", bmp.RouteMonitorMsg},
		{"StatsReport too short", bmp.StatsReportMsg},
		{"PeerDown too short", bmp.PeerDownMsg},
		{"PeerUp too short", bmp.PeerUpMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a message whose MessageLength claims only CommonHeaderLength+1 bytes
			// (too short to hold a 42-byte Per-Peer Header).
			truncLen := bmp.CommonHeaderLength + 1
			b := make([]byte, truncLen)
			b[0] = 3 // BMP version
			binary.BigEndian.PutUint32(b[1:5], uint32(truncLen))
			b[5] = tt.msgType

			producerQueue := make(chan bmp.Message, 4)
			p := &parser{producerQueue: producerQueue, config: &Config{}}
			// Must not panic.
			p.parsingWorker(b)
			// No message should have been produced.
			close(producerQueue)
			if n := len(producerQueue); n != 0 {
				t.Errorf("expected 0 messages for truncated %s, got %d", tt.name, n)
			}
		})
	}
}

// TestParsingWorkerStatsReportTooShortForCount verifies that a StatsReport whose
// MessageLength claims exactly CommonHeaderLength+PerPeerHeaderLength (no room for
// the 4-byte StatsCount) is rejected with a clear log before reaching the unmarshaller.
func TestParsingWorkerStatsReportTooShortForCount(t *testing.T) {
	emptyPPH := make([]byte, bmp.PerPeerHeaderLength)
	// Build a StatsReport message with no body (length = header + per-peer only).
	truncLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength
	b := make([]byte, truncLen)
	b[0] = 3
	binary.BigEndian.PutUint32(b[1:5], uint32(truncLen))
	b[5] = bmp.StatsReportMsg
	copy(b[6:], emptyPPH)

	producerQueue := make(chan bmp.Message, 4)
	p := &parser{producerQueue: producerQueue, config: &Config{}}
	// Must not panic.
	p.parsingWorker(b)
	if n := len(producerQueue); n != 0 {
		t.Errorf("expected 0 messages for truncated StatsReport, got %d", n)
	}
}

func TestParsingWorker(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "test 1",
			input: []byte{3, 0, 0, 0, 32, 4, 0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49, 3, 0, 0, 0, 234, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 103, 0, 0, 19, 206, 57, 112, 1, 254, 94, 98, 129, 171, 0, 0, 215, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 128, 0, 179, 131, 152, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 75, 1, 4, 19, 206, 0, 90, 57, 112, 1, 254, 46, 2, 44, 2, 0, 1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1, 1, 4, 0, 1, 0, 4, 1, 4, 0, 2, 0, 4, 1, 4, 0, 1, 0, 128, 1, 4, 0, 2, 0, 128, 65, 4, 0, 0, 19, 206},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producerQueue := make(chan bmp.Message, 1)
			p := &parser{
				producerQueue: producerQueue,
				config:        &Config{EnableRawMode: false},
			}
			p.parsingWorker(tt.input)
		})
	}
}

// TestParserRawMode tests parser in raw mode
func TestParserRawMode(t *testing.T) {
	input := []byte{3, 0, 0, 0, 32, 4, 0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49}

	producerQueue := make(chan bmp.Message, 1)
	p := &parser{
		producerQueue: producerQueue,
		config:        &Config{EnableRawMode: true},
	}

	p.parsingWorker(input)

	// Check that a message was produced
	select {
	case msg := <-producerQueue:
		if msg.Payload == nil {
			t.Error("Expected payload in raw mode, got nil")
		}
		if _, ok := msg.Payload.(*bmp.RawMessage); !ok {
			t.Errorf("Expected RawMessage payload, got %T", msg.Payload)
		}
	default:
		t.Error("Expected message in producer queue, got none")
	}
}

// TestParserNormalMode tests parser in normal (parsed) mode
func TestParserNormalMode(t *testing.T) {
	input := []byte{3, 0, 0, 0, 32, 4, 0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49}

	producerQueue := make(chan bmp.Message, 1)
	p := &parser{
		producerQueue: producerQueue,
		config:        &Config{EnableRawMode: false},
	}

	p.parsingWorker(input)
	// In normal mode, initiation messages don't produce output to queue
	// This test just verifies no panic occurs
}

// TestNewParser tests parser constructor
func TestNewParser(t *testing.T) {
	queue := make(chan []byte)
	producerQueue := make(chan bmp.Message)
	stop := make(chan struct{})

	// Test with nil config
	p := NewParser(queue, producerQueue, stop, nil)
	if p == nil {
		t.Fatal("NewParser returned nil")
	}
	if p.config == nil {
		t.Fatal("NewParser should set default config when nil provided")
	}
	if p.config.EnableRawMode {
		t.Error("Default config should have EnableRawMode = false")
	}

	// Test with explicit config
	config := &Config{EnableRawMode: true}
	p2 := NewParser(queue, producerQueue, stop, config)
	if p2.config.EnableRawMode != true {
		t.Error("NewParser should use provided config")
	}
}
