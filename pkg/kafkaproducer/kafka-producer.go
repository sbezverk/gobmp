package kafkaproducer

import (
	"fmt"
	"math"
	"net"
	"strconv"

	"github.com/golang/glog"
	kafka "github.com/segmentio/kafka-go"
)

// KafkaProducer defines methods to act as a Kafka producer
type KafkaProducer interface {
}

type kafkaProducer struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

// NewKafkaProducerClient instantiates a new instance of a Kafka producer client
func NewKafkaProducerClient(kafkaSrv string) (KafkaProducer, error) {
	glog.Infof("Initializing Kafka producer client")
	if err := validator(kafkaSrv); err != nil {
		glog.Errorf("Failed to validate Kafka server address %s with error: %+v", kafkaSrv, err)
		return nil, err
	}
	kafkaConn, err := kafka.Dial("tcp", kafkaSrv)
	if err != nil {
		glog.Errorf("Failed to dial to Kafka with error: %+v", err)
		return nil, err
	}
	glog.V(5).Infof("Connected to Kafka server at: %s", kafkaConn.RemoteAddr().String())
	t := kafka.TopicConfig{
		Topic:             "blahblah",
		NumPartitions:     1,
		ReplicationFactor: 1,
	}
	if err := kafkaConn.CreateTopics(t); err != nil {
		glog.Errorf("Failed to create Kafka topic with error: %+v", err)
		return nil, err
	}
	glog.V(5).Infof("Create Kafka topic %s succeeded", t.Topic)

	p, err := kafkaConn.ReadPartitions(t.Topic)
	if err != nil {
		glog.Errorf("Failed to read particions for Kafka topic with error: %+v", err)
		return nil, err
	}
	glog.V(5).Infof("Getting partitions for Kafka topic %s succeeded", t.Topic)

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
