package gobmpsrv

import (
	"testing"
	"time"
)

func TestConnectSpeaker_CancelledDialExitsWithoutRetry(t *testing.T) {
	srv, cleanup := newConnectSpeakerSrv()
	defer func() { cleanup(); srv.wg.Wait() }()
	// stopConnector cancels this context before closing the stop channel.
	// Keep the channel open to exercise that interval deterministically,
	// rather than exiting through the loop's earlier stop-channel select.
	srv.connectorCancel()
	speaker := &bgpSpeaker{Address: "127.0.0.1:1", retryDelay: time.Second}
	done := runConnectSpeaker(srv, speaker)
	select {
	case <-done:
	case <-time.After(time.Second):
		speaker.mu.Lock()
		delay, nextAttempt := speaker.retryDelay, speaker.nextAttempt
		speaker.mu.Unlock()
		t.Fatalf("cancelled dial did not exit: retry delay %v, next attempt %v", delay, nextAttempt)
	}
	speaker.mu.Lock()
	defer speaker.mu.Unlock()
	if speaker.retryDelay != time.Second || !speaker.nextAttempt.IsZero() || speaker.isConnected {
		t.Fatalf("cancelled dial changed retry state: delay %v, next attempt %v, connected %v", speaker.retryDelay, speaker.nextAttempt, speaker.isConnected)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.clients) != 0 {
		t.Fatalf("cancelled dial registered %d client workers", len(srv.clients))
	}
}
