package nats

import (
	"errors"
	"sync"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestStop_WaitsForAcks checks that Stop returns only once the outstanding
// acknowledgements are in.
func TestStop_WaitsForAcks(t *testing.T) {
	acked := make(chan struct{})
	p := newPublisher(nil, &fakeJetStream{completeFn: func() <-chan struct{} { return acked }})
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("k"), []byte("{}")); err != nil {
		t.Fatalf("PublishMessage: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned with acknowledgements outstanding")
	case <-time.After(50 * time.Millisecond):
	}
	close(acked)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return once the acknowledgements were in")
	}
	p.Stop() // a second Stop is a no-op
}

// TestStop_AckTimeout checks that Stop gives up on acknowledgements after
// stopTimeout.
func TestStop_AckTimeout(t *testing.T) {
	old := stopTimeout
	stopTimeout = 20 * time.Millisecond
	defer func() { stopTimeout = old }()
	p := newPublisher(nil, &fakeJetStream{completeFn: func() <-chan struct{} { return make(chan struct{}) }})
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not give up on the acknowledgements")
	}
}

func TestPublishAfterStop_ReturnsError(t *testing.T) {
	published := 0
	p := newPublisher(nil, &fakeJetStream{publishFn: func(*natsgo.Msg) error {
		published++
		return nil
	}})
	p.Stop()
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")); !errors.Is(err, errStopped) {
		t.Errorf("PublishMessage after Stop: error = %v, want %v", err, errStopped)
	}
	if published != 0 {
		t.Errorf("%d messages reached JetStream after Stop", published)
	}
}

// TestPublish_WaitsWhileStalled checks that a publish keeps waiting while
// too many acknowledgements are outstanding, publishes once there is room,
// and gives up when Stop is called.
func TestPublish_WaitsWhileStalled(t *testing.T) {
	var mu sync.Mutex
	stalls, subjects := 3, []string{}
	p := newPublisher(nil, &fakeJetStream{publishFn: func(m *natsgo.Msg) error {
		mu.Lock()
		defer mu.Unlock()
		if stalls > 0 {
			stalls--
			return natsgo.ErrTooManyStalledMsgs
		}
		subjects = append(subjects, m.Subject)
		return nil
	}})
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")); err != nil {
		t.Fatalf("PublishMessage: %v", err)
	}
	mu.Lock()
	if len(subjects) != 1 || subjects[0] != peerTopic {
		t.Fatalf("published to %v, want [%s]", subjects, peerTopic)
	}
	stalls = 1 << 30
	mu.Unlock()
	done := make(chan error)
	go func() { done <- p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")) }()
	time.Sleep(10 * time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errStopped) {
			t.Errorf("stalled PublishMessage: error = %v, want %v", err, errStopped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled publish did not give up on Stop")
	}
	<-stopped
}

func TestConfigWithDefaults(t *testing.T) {
	tests := []struct {
		name    string
		in      Config
		want    Config
		wantErr bool
	}{
		{name: "zero", in: Config{}, want: Config{MaxPendingAcks: DefaultMaxPendingAcks, AckTimeout: DefaultAckTimeout}},
		{name: "set", in: Config{MaxPendingAcks: 16, AckTimeout: time.Second}, want: Config{MaxPendingAcks: 16, AckTimeout: time.Second}},
		{name: "negative pending", in: Config{MaxPendingAcks: -1}, wantErr: true},
		{name: "negative timeout", in: Config{AckTimeout: -time.Second}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.withDefaults()
			if (err != nil) != tt.wantErr {
				t.Fatalf("withDefaults() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("withDefaults() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestNewPublisherWithConfig_Invalid(t *testing.T) {
	if _, err := NewPublisherWithConfig(nil); err == nil {
		t.Error("NewPublisherWithConfig(nil): error = nil, want an error")
	}
	if _, err := NewPublisherWithConfig(&Config{ServerAddress: "nats://127.0.0.1:1", MaxPendingAcks: -1}); err == nil {
		t.Error("NewPublisherWithConfig with negative MaxPendingAcks: error = nil, want an error")
	}
}

// TestErrorLog_RateLimited checks that failures within a second of a logged
// one are counted, not logged.
func TestErrorLog_RateLimited(t *testing.T) {
	var l errorLog
	m := &natsgo.Msg{Subject: peerTopic}
	err := errors.New("ack timeout")
	l.log(m, err)
	first := l.last
	for i := 0; i < 5; i++ {
		l.log(m, err)
	}
	if l.last != first || l.suppressed != 5 {
		t.Errorf("after 6 failures within a second: last moved %v, %d suppressed, want 5", l.last != first, l.suppressed)
	}
	l.last = l.last.Add(-time.Second)
	l.log(m, err)
	if l.suppressed != 0 {
		t.Errorf("a failure a second later left %d suppressed, want 0", l.suppressed)
	}
}
