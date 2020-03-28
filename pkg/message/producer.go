package message

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

type producer struct {
	publisher pub.Publisher
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	for {
		select {
		case msg := <-queue:
			go p.producingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		default:
		}
	}
}

func (p *producer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		p.producePeerUpMessage(msg)
	case *bmp.PeerDownMessage:
		p.producePeerDownMessage(msg)
	case *bmp.RouteMonitor:
		p.produceRouteMonitorMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to kafka, ignoring it...", obj)
	}
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher) Producer {
	return &producer{
		publisher: publisher,
	}
}
