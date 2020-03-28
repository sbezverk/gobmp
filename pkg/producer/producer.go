package producer

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// Producer defines methods to act as a Kafka producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

// topicConnection defines per topic connection and connection related information
type topicConnection struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

type producer struct {
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
