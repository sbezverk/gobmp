package message

import (
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown
)

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

type producer struct {
	publisher      pub.Publisher
	speakerIP      string
	speakerHash    string
	addPathCapable map[int]bool
	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// tableLock protects tableInfoMap as it is accessed from multiple goroutines
	tableLock sync.Mutex
	// tableInfoMap keeps Information TLVs per Peer BGP ID and Peer Distinguisher
	tableInfoMap map[string][]bmp.InformationalTLV
}

func (p *producer) GetTableName(bgpID, rd string) string {
	p.tableLock.Lock()
	defer p.tableLock.Unlock()
	tn := ""
	for _, tlv := range p.tableInfoMap[bgpID+rd] {
		if tlv.InformationType == 3 {
			tn += tlv.Information.(string)
		}
	}

	return tn
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
		}
	}
}

func (p *producer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		p.producePeerMessage(peerUP, msg)
	case *bmp.PeerDownMessage:
		p.producePeerMessage(peerDown, msg)
	case *bmp.RouteMonitor:
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		p.produceStatsMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to the producer, ignoring it...", obj)
	}
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher, splitAF bool) Producer {
	return &producer{
		publisher:      publisher,
		splitAF:        splitAF,
		addPathCapable: make(map[int]bool),
		tableInfoMap:   make(map[string][]bmp.InformationalTLV),
	}
}
