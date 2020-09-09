package message

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown
)

const (
	// NumberOfWorkers is maximum number of concurrent go routines created by the processor to process mesages.
	NumberOfWorkers = 102400
)

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

type producer struct {
	publisher   pub.Publisher
	speakerIP   string
	speakerHash string
	as4Capable  bool
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	pool := make(chan struct{}, NumberOfWorkers)
	for {
		select {
		case msg := <-queue:
			// Writing to Pool channel to reserve a worker slot
			pool <- struct{}{}
			go p.producingWorker(msg, pool)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func (p *producer) producingWorker(msg bmp.Message, pool chan struct{}) {
	defer func() {
		// Reading from Pool channel to release the worker slot
		<-pool
	}()
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		p.producePeerMessage(peerUP, msg)
	case *bmp.PeerDownMessage:
		p.producePeerMessage(peerDown, msg)
	case *bmp.RouteMonitor:
		p.produceRouteMonitorMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to the producer, ignoring it...", obj)
	}
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher) Producer {
	return &producer{
		publisher: publisher,
	}
}
