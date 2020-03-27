package kafkaproducer

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
	kafka "github.com/segmentio/kafka-go"
)

// Define constants for each topic name
const (
	peerTopic = "gobmp.parsed.peer"
)

var (
	// topics defines a list of topic to initialize and connect,
	// initialization is done as a part of NewKafkaProducerClient func.
	topicNames = []string{peerTopic}
)

// KafkaProducer defines methods to act as a Kafka producer
type KafkaProducer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
}

// topicConnection defines per topic connection and connection related information
type topicConnection struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

type kafkaProducer struct {
	sync.Mutex
	// topics is map of topics' connections, keyed by the topic name
	topics map[string]*topicConnection
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

func (k *kafkaProducer) produceMessage(topic string, key string, msg []byte) error {
	k.Lock()
	defer k.Unlock()
	t, ok := k.topics[topic]
	if !ok {
		return fmt.Errorf("topic %s in not initialized", topic)
	}
	leaderAddr := fmt.Sprintf("%s:%d", t.partitions[0].Leader.Host, t.partitions[0].Leader.Port)
	kafkaConn, err := kafka.DefaultDialer.DialLeader(context.TODO(), "tcp", leaderAddr, t.partitions[0].Topic, t.partitions[0].Leader.ID)
	if err != nil {
		glog.Errorf("Failed to connect to the topic %s's partition leader with error: %+v", topic, err)
		return err
	}
	n, err := kafkaConn.WriteMessages(kafka.Message{
		Key:   []byte(key),
		Value: msg,
		Time:  time.Now(),
	})
	if err != nil {
		glog.Errorf("Failed to write test message to the topic %s with error: %+v", topic, err)
		return err
	}
	glog.V(5).Infof("Successfully wrote %d bytes to Kafka topic %s", n, topic)

	return nil
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

	topics, err := initTopic(conn)
	if err != nil {
		glog.Errorf("Failed to initialize topics with error: %+v", err)
		return nil, err
	}

	return &kafkaProducer{
		topics: topics,
	}, nil
}

func initTopic(conn *kafka.Conn) (map[string]*topicConnection, error) {
	topics := make(map[string]*topicConnection)
	for _, tn := range topicNames {
		t := kafka.TopicConfig{
			Topic:             tn,
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
			// TODO, after the topic gets created, there is a leader election which might take some time, during which
			// ReadPartitions will return error: [5] Leader Not Available. Need to add more sophisticated retry logic.
			for retry := 1; ; {
				p, err = conn.ReadPartitions(t.Topic)
				if err == nil {
					break
				}
				if err != nil && retry >= 5 {
					glog.Errorf("Failed to read particions for Kafka topic with error: %+v", err)
					return nil, err
				}
				glog.Warningf("Failed to read particions for Kafka topic %s with error: %+v, retry: %d", t.Topic, err, retry)
				retry++
				time.Sleep(6 * time.Second)
			}
		} else {
			glog.V(5).Infof("Kafka topic %s already exists", t.Topic)
		}

		glog.V(5).Infof("Getting partitions for Kafka topic %s succeeded, partitions: %+v", t.Topic, p)

		leaderAddr := fmt.Sprintf("%s:%d", p[0].Leader.Host, p[0].Leader.Port)
		kafkaConn, err := kafka.DefaultDialer.DialLeader(context.TODO(), "tcp", leaderAddr, p[0].Topic, p[0].Leader.ID)
		// Adding topic and its connection properties into the map
		topics[tn] = &topicConnection{
			// TODO kafkaConn represents connection to the topic leader at the time of initialization
			// what if leader changes later? COnsider adding leader connection refresh logic.
			kafkaConn:  kafkaConn,
			partitions: p,
		}
	}

	return topics, nil
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
