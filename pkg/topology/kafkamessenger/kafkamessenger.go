package kafkamessenger

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/tools"
	"github.com/sbezverk/gobmp/pkg/topology/processor"
	kafkago "github.com/segmentio/kafka-go"
)

// Define constants for each topic name
const (
	peerTopic             = "gobmp.parsed.peer"
	unicastMessageTopic   = "gobmp.parsed.unicast_prefix"
	lsNodeMessageTopic    = "gobmp.parsed.ls_node"
	lsLinkMessageTopic    = "gobmp.parsed.ls_link"
	l3vpnMessageTopic     = "gobmp.parsed.l3vpn"
	lsPrefixMessageTopic  = "gobmp.parsed.ls_prefix"
	lsSRv6SIDMessageTopic = "gobmp.parsed.ls_srv6_sid"
	evpnMessageTopic      = "gobmp.parsed.evpn"
)

var (
	topics = map[string]int{
		peerTopic:             bmp.PeerStateChangeMsg,
		unicastMessageTopic:   bmp.UnicastPrefixMsg,
		lsNodeMessageTopic:    bmp.LSNodeMsg,
		lsLinkMessageTopic:    bmp.LSLinkMsg,
		l3vpnMessageTopic:     bmp.L3VPNMsg,
		lsPrefixMessageTopic:  bmp.LSPrefixMsg,
		lsSRv6SIDMessageTopic: bmp.LSSRv6SIDMsg,
		evpnMessageTopic:      bmp.EVPNMsg,
	}
)

// Srv defines required method of a processor server
type Srv interface {
	Start() error
	Stop() error
}

type kafka struct {
	stop    chan struct{}
	conn    *kafkago.Conn
	brokers []string
	proc    processor.Messenger
}

// NewKafkaMessenger returns an instance of a kafka consumer acting as a messenger server
func NewKafkaMessenger(kafkaSrv string, messenger processor.Messenger) (Srv, error) {
	glog.Infof("NewKafkaMessenger")
	if err := tools.HostAddrValidator(kafkaSrv); err != nil {
		return nil, err
	}
	conn, err := kafkago.Dial("tcp", kafkaSrv)
	if err != nil {
		glog.Errorf("Failed to dial to Kafka with error: %+v", err)
		return nil, err
	}
	brokers, err := conn.Brokers()
	if err != nil {
		return nil, err
	}
	k := &kafka{
		stop: make(chan struct{}),
		conn: conn,
		proc: messenger,
	}
	for _, broker := range brokers {
		k.brokers = append(k.brokers, fmt.Sprintf("%s:%d", broker.Host, broker.Port))
	}
	glog.V(5).Infof("Connected to Kafka server at: %s", conn.RemoteAddr().String())

	return k, nil
}

func (k *kafka) Start() error {
	// Starting readers for each topic name and type defined in topics map
	for topicName, topicType := range topics {
		go k.topicReader(topicType, topicName)
	}

	return nil
}

func (k *kafka) Stop() error {
	return nil
}

func (k *kafka) topicReader(topicType int, topicName string) {
	for {
		glog.Infof("Starting Kafka reader for topic: %s", topicName)
		r := kafkago.NewReader(kafkago.ReaderConfig{
			Brokers:   k.brokers,
			Topic:     topicName,
			Partition: 0,
			MinBytes:  0,
			MaxBytes:  10e6, // 10MB
		})
		defer r.Close()
		select {
		case <-k.stop:
			return
		default:
		}
		if err := func() error {
			for {
				m, err := r.ReadMessage(context.Background())
				if err != nil {
					return err
				}
				k.proc.SendMessage(topicType, m.Value)
				select {
				case <-k.stop:
					return nil
				default:
				}
			}
		}(); err == nil {
			return
		}
	}
}
