package kafkaproducer

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	kafka "github.com/segmentio/kafka-go"
)

const (
	gobmpTopic = "gobmp.feed"
)

// KafkaProducer defines methods to act as a Kafka producer
type KafkaProducer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

type kafkaProducer struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

// Producer dispatches kafka workers upon request received from the channel
func (k *kafkaProducer) Producer(queue chan bmp.Message, stop chan struct{}) {
	for {
		select {
		case msg := <-queue:
			go k.producingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		default:
		}
	}
}

func (k *kafkaProducer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		k.producePeerUpMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to kafka, ignoring it...", obj)
	}

}

func (k *kafkaProducer) producePeerUpMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("Kafka PeerUPMessage: per PeerHeader is missing, cannot construct PeerStateChange message")
		return
	}
	peerUpMsg, ok := msg.Payload.(*bmp.PeerUpMessage)
	if !ok {
		glog.Errorf("Kafka PeerUPMessage: got invalid Payload type in bmp.Message")
		return
	}
	glog.Infof("Kafka PeerUpMessage: perPeerHeader: %+v", *msg.PeerHeader)
	glog.Infof("Kafka PeerUpMessage: PeerUp: %+v", peerUpMsg)

	m := PeerStateChange{
		Action:     "up",
		RemoteASN:  int16(msg.PeerHeader.PeerAS),
		PeerRD:     msg.PeerHeader.PeerDistinguisher.String(),
		Timestamp:  msg.PeerHeader.PeerTimestamp,
		RemotePort: int(peerUpMsg.RemotePort),
		LocalPort:  int(peerUpMsg.LocalPort),
	}
	if msg.PeerHeader.FlagV {
		m.IsIPv4 = false
		m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress).To16().String()
		m.LocalIP = net.IP(peerUpMsg.LocalAddress).To16().String()
		m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To16().String()
	} else {
		m.IsIPv4 = true
		m.RemoteIP = net.IP(msg.PeerHeader.PeerAddress[12:]).To4().String()
		m.LocalIP = net.IP(peerUpMsg.LocalAddress[12:]).To4().String()
		m.RemoteBGPID = net.IP(msg.PeerHeader.PeerBGPID).To4().String()
	}

	b, err := json.Marshal(&m)
	if err != nil {
		glog.Errorf("Kafka PeerUPMessage: failed to Marshal PeerStateChange struct with error: %+v", err)
		return
	}
	glog.Infof("Kafka PeerUPMessage: PeerStateChange raw: %+v json: %s", m, string(b))
}

// NewKafkaProducerClient instantiates a new instance of a Kafka producer client
func NewKafkaProducerClient(kafkaSrv string) (KafkaProducer, error) {
	glog.Infof("Initializing Kafka producer client")
	if err := validator(kafkaSrv); err != nil {
		glog.Errorf("Failed to validate Kafka server address %s with error: %+v", kafkaSrv, err)
		return nil, err
	}

	conn, err := kafka.Dial("tcp", kafkaSrv)
	if err != nil {
		glog.Errorf("Failed to dial to Kafka with error: %+v", err)
		return nil, err
	}
	glog.V(5).Infof("Connected to Kafka server at: %s", conn.RemoteAddr().String())
	t := kafka.TopicConfig{
		Topic:             gobmpTopic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	}
	// Getting Topic from Kafka
	p, err := conn.ReadPartitions(t.Topic)
	if err != nil {
		// Topic is not found, attempting to Create it
		if err := conn.CreateTopics(t); err != nil {
			glog.Errorf("Failed to create Kafka topic with error: %+v", err)
			return nil, err
		}
		glog.V(5).Infof("Create Kafka topic %s succeeded", t.Topic)
		// Getting Topic from Kafka again, if failing again, then give up and return an error.
		p, err = conn.ReadPartitions(t.Topic)
		if err != nil {
			glog.Errorf("Failed to read particions for Kafka topic with error: %+v", err)
			return nil, err
		}
	}
	glog.V(5).Infof("Getting partitions for Kafka topic %s succeeded, partitions: %+v", t.Topic, p)

	leaderAddr := fmt.Sprintf("%s:%d", p[0].Leader.Host, p[0].Leader.Port)
	kafkaConn, err := kafka.DefaultDialer.DialLeader(context.TODO(), "tcp", leaderAddr, p[0].Topic, p[0].Leader.ID)
	if err != nil {
		glog.Errorf("Failed to connect to the particion's leader with error: %+v", err)
		return nil, err
	}
	n, err := kafkaConn.WriteMessages(kafka.Message{
		Key:   []byte("test message key"),
		Value: []byte("test message value"),
		Headers: []kafka.Header{
			{
				Key:   "Header key",
				Value: []byte("Header value"),
			},
		},
	})
	if err != nil {
		glog.Errorf("Failed to write test message to the topic %s with error: %+v", t.Topic, err)
		return nil, err
	}
	glog.V(5).Infof("Successfully wrote %d bytes to Kafka topic %s", n, t.Topic)

	return &kafkaProducer{
		kafkaConn:  kafkaConn,
		partitions: p,
	}, nil
}

func validator(addr string) error {
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || port == "" {
		return fmt.Errorf("host or port cannot be ''")
	}
	// Try to resolve if the hostname was used in the address
	if ip, err := net.LookupIP(host); err != nil || ip == nil {
		// Check if IP address was used in address instead of a host name
		if net.ParseIP(host) == nil {
			return fmt.Errorf("fail to parse host part of address")
		}
	}
	np, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("fail to parse port with error: %w", err)
	}
	if np == 0 || np > math.MaxUint16 {
		return fmt.Errorf("the value of port is invalid")
	}
	return nil
}
