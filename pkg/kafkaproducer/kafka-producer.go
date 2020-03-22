package kafkaproducer

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/golang/glog"
	kafka "github.com/segmentio/kafka-go"
)

const (
	gobmpTopic = "gobmp.feed"
)

// KafkaProducer defines methods to act as a Kafka producer
type KafkaProducer interface {
	Producer(queue chan []byte, stop chan struct{})
}

type kafkaProducer struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

// Producer dispatches kafka workers upon request received from the channel
func (k *kafkaProducer) Producer(queue chan []byte, stop chan struct{}) {
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

func (k *kafkaProducer) producingWorker(j []byte) {
	glog.Infof("get JSON message to push to kafka")
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
