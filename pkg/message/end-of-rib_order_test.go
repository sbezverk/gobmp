package message

import (
	"encoding/json"
	"testing"
	"testing/synctest"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// The route publication stays blocked while later input is available. A
// settled synctest bubble exposes overtaking without sleeps or scheduler luck.
type eorOrderingPublisher struct {
	started       chan recordedMsg
	routeReturned chan struct{}
	release       chan struct{}
}

func (p *eorOrderingPublisher) PublishMessage(kind int, _, payload []byte) error {
	p.started <- recordedMsg{msgType: kind, payload: append([]byte(nil), payload...)}
	if kind == bmp.UnicastPrefixMsg {
		var route struct {
			IsEOR bool `json:"is_eor"`
		}
		if err := json.Unmarshal(payload, &route); err != nil {
			return err
		}
		if !route.IsEOR {
			<-p.release
			close(p.routeReturned)
		}
	}
	return nil
}
func (p *eorOrderingPublisher) Stop() {}

func TestProducerEndOfRIBWaitsForEarlierRoute(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pub := &eorOrderingPublisher{
			started: make(chan recordedMsg, 8), routeReturned: make(chan struct{}), release: make(chan struct{}),
		}
		p := NewProducer(pub, false).(*producer)
		ph := makePeerHeader(t, bmp.PeerType0, 0)
		p.producingWorker(bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
		<-pub.started // Initial PeerUp is complete before the blocked route.

		queue, stop := make(chan bmp.Message, 3), make(chan struct{})
		released := false
		t.Cleanup(func() {
			if !released {
				close(pub.release)
			}
			close(stop)
			synctest.Wait()
		})
		go p.Producer(queue, stop)
		queue <- bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, nil, []byte{24, 192, 0, 2})}
		synctest.Wait()
		if got := <-pub.started; got.msgType != bmp.UnicastPrefixMsg {
			t.Fatalf("first route type = %d", got.msgType)
		}
		queue <- bmp.Message{PeerHeader: ph, Payload: eorWire(t, nil, nil, nil)}
		queue <- bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 4}}
		synctest.Wait()
		if got := len(pub.started); got != 0 {
			t.Errorf("%d later publications overtook the blocked route", got)
		}
		if _, exists := p.identities[ph.PeerIdentity()]; !exists {
			t.Error("PeerDown removed identity before the earlier route returned")
		}
		close(pub.release)
		released = true
		synctest.Wait()
		select {
		case <-pub.routeReturned:
		default:
			t.Error("ordinary route publication did not return")
		}
		for i, want := range []int{bmp.UnicastPrefixMsg, bmp.EndOfRIBMsg, bmp.PeerStateChangeMsg} {
			select {
			case got := <-pub.started:
				if got.msgType != want {
					t.Errorf("publication %d type = %d, want %d", i, got.msgType, want)
				}
				if i == 0 {
					var marker struct {
						IsEOR bool `json:"is_eor"`
					}
					if err := json.Unmarshal(got.payload, &marker); err != nil {
						t.Fatal(err)
					}
					if !marker.IsEOR {
						t.Error("compatibility publication is not an EOR")
					}
				}
			default:
				t.Errorf("publication %d missing", i)
			}
		}
		if len(pub.started) != 0 {
			t.Error("unexpected extra publication")
		}
		if _, exists := p.identities[ph.PeerIdentity()]; exists {
			t.Error("PeerDown did not remove identity")
		}
	})
}
