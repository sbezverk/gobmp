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

type PerTableProperties struct {
	addPathCapable map[int]bool
	// tableInfoTLVs holds Informational TLVs received with Peer Up message for the given BGP ID + RD combination
	tableInfoTLVs []bmp.InformationalTLV
}

type producer struct {
	publisher   pub.Publisher
	speakerIP   string
	speakerHash string
	// addPathCapable map[int]bool
	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// tableLock protects tableProperties as it is accessed from multiple goroutines
	tableLock sync.RWMutex
	// tableProperties keeps table specific properties per BGP ID + RD combination
	tableProperties map[string]PerTableProperties
}

func (p *producer) GetTableName(bgpID, rd string) string {
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()
	tn := ""

	if properties, ok := p.tableProperties[bgpID+rd]; ok {
		for _, tlv := range properties.tableInfoTLVs {
			if tlv.InformationType == 3 {
				tn += tlv.Information.(string)
			}
		}
	}
	return tn
}

func (p *producer) GetAddPathCapability(tableKey string) map[int]bool {
	var m map[int]bool
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()
	m = p.tableProperties[tableKey].addPathCapable

	return m
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
		publisher: publisher,
		splitAF:   splitAF,
		// addPathCapable:  make(map[int]bool),
		tableProperties: make(map[string]PerTableProperties),
	}
}
