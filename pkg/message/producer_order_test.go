package message

import (
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

type orderedPublisher struct{ messages chan int }

func (p *orderedPublisher) PublishMessage(kind int, _, _ []byte) error {
	p.messages <- kind
	return nil
}
func (p *orderedPublisher) Stop() {}

func sendOrderedMessage(t *testing.T, queue chan bmp.Message, msg bmp.Message) {
	t.Helper()
	select {
	case queue <- msg:
	case <-time.After(time.Second):
		t.Fatal("producer stopped accepting messages")
	}
}

func awaitOrderedProducer(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("producer did not stop")
	}
}

func TestProducerBuffersDataBeforePeerUp(t *testing.T) {
	pub := &orderedPublisher{messages: make(chan int, 8)}
	p := NewProducer(pub, false)
	queue, stop := make(chan bmp.Message), make(chan struct{})
	done := make(chan struct{})
	go func() { p.Producer(queue, stop); close(done) }()
	t.Cleanup(func() { close(stop); awaitOrderedProducer(t, done) })

	ph := makePeerHeader(t, bmp.PeerType0, 0)
	route := bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: &bgp.Update{
		NLRI: []byte{24, 192, 0, 2}, BaseAttributes: &bgp.BaseAttributes{},
	}}}
	stats := bmp.Message{PeerHeader: ph, Payload: &bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{{
		InformationType: 0, InformationLength: 4, Information: []byte{0, 0, 0, 42},
	}}}}
	// Both messages arrive before PeerUp and must be replayed after it.
	sendOrderedMessage(t, queue, route)
	sendOrderedMessage(t, queue, stats)
	sendOrderedMessage(t, queue, bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
	sendOrderedMessage(t, queue, route)
	sendOrderedMessage(t, queue, stats)

	for i, want := range []int{
		bmp.PeerStateChangeMsg,
		bmp.UnicastPrefixMsg,
		bmp.StatsReportMsg,
		bmp.UnicastPrefixMsg,
		bmp.StatsReportMsg,
	} {
		select {
		case got := <-pub.messages:
			if got != want {
				t.Fatalf("message %d type = %d, want %d", i, got, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("message %d was not published", i)
		}
	}
	// A final synchronous message is a barrier for all earlier input.
	sendOrderedMessage(t, queue, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 4}})
	if got := <-pub.messages; got != bmp.PeerStateChangeMsg {
		t.Fatalf("unexpected message after valid data: type %d", got)
	}
}

func TestProducerDiscardsPrePeerUpBufferOnPeerDown(t *testing.T) {
	rec := &recordingPublisher{}
	p := NewProducer(rec, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0)

	p.producingWorker(bmp.Message{
		PeerHeader: ph,
		Payload:    &bmp.RouteMonitor{Update: &bgp.Update{NLRI: []byte{24, 192, 0, 2}, BaseAttributes: &bgp.BaseAttributes{}}},
	})
	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 4}})
	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})

	if len(p.prePeerUp) != 0 {
		t.Fatalf("pre-PeerUp buffer length = %d, want 0", len(p.prePeerUp))
	}
	if len(rec.msgs) != 2 {
		t.Fatalf("published messages = %d, want PeerDown and PeerUp only", len(rec.msgs))
	}
}

func TestProducerBoundsPrePeerUpBuffer(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	for i := 0; i < maxPrePeerUpMessages+1; i++ {
		p.producingWorker(bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.StatsReport{},
		})
	}

	if len(p.prePeerUp) != maxPrePeerUpMessages {
		t.Fatalf("pre-PeerUp buffer length = %d, want %d", len(p.prePeerUp), maxPrePeerUpMessages)
	}
	if p.prePeerUpBytes > maxPrePeerUpBytes {
		t.Fatalf("pre-PeerUp buffer bytes = %d, exceeds %d", p.prePeerUpBytes, maxPrePeerUpBytes)
	}
}

func TestProducerStopsBeforePeerUp(t *testing.T) {
	p := NewProducer(&orderedPublisher{messages: make(chan int, 1)}, false)
	queue, stop := make(chan bmp.Message), make(chan struct{})
	done := make(chan struct{})
	go func() { p.Producer(queue, stop); close(done) }()
	sendOrderedMessage(t, queue, bmp.Message{Payload: &bmp.RouteMonitor{}})
	sendOrderedMessage(t, queue, bmp.Message{Payload: &bmp.StatsReport{}})
	close(stop)
	awaitOrderedProducer(t, done)
}

func TestProducerClosedQueueReturns(t *testing.T) {
	queue := make(chan bmp.Message)
	close(queue)
	done := make(chan struct{})
	go func() { NewProducer(nil, false).Producer(queue, nil); close(done) }()
	awaitOrderedProducer(t, done)
}

type blockedOrderedPublisher struct{ entered, release chan struct{} }

func (p *blockedOrderedPublisher) PublishMessage(_ int, _, _ []byte) error {
	close(p.entered)
	<-p.release
	return nil
}
func (p *blockedOrderedPublisher) Stop() {}

func TestProducersRemainIndependentDuringPublish(t *testing.T) {
	blocked := &blockedOrderedPublisher{entered: make(chan struct{}), release: make(chan struct{})}
	pub := &orderedPublisher{messages: make(chan int, 1)}
	queue1, queue2 := make(chan bmp.Message), make(chan bmp.Message)
	stop1, stop2 := make(chan struct{}), make(chan struct{})
	done1, done2 := make(chan struct{}), make(chan struct{})
	go func() { NewProducer(blocked, false).Producer(queue1, stop1); close(done1) }()
	go func() { NewProducer(pub, false).Producer(queue2, stop2); close(done2) }()
	t.Cleanup(func() {
		close(stop1)
		close(stop2)
		// PublishMessage has no cancellation API: stopping the producer cannot
		// interrupt an active backend call. Release it before waiting for exit.
		close(blocked.release)
		awaitOrderedProducer(t, done1)
		awaitOrderedProducer(t, done2)
	})
	msg := bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: buildPeerUpMessage(t, "192.0.2.1")}
	sendOrderedMessage(t, queue1, msg)
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("first producer did not reach publisher")
	}
	sendOrderedMessage(t, queue2, msg)
	select {
	case <-pub.messages:
	case <-time.After(time.Second):
		t.Fatal("one connection blocked another connection's producer")
	}
}
