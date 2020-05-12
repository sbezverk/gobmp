package kafka

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
	"github.com/sbezverk/gobmp/pkg/pub"
	kafka "github.com/segmentio/kafka-go"
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
	// topics defines a list of topic to initialize and connect,
	// initialization is done as a part of NewKafkaPublisher func.
	topicNames = []string{
		peerTopic,
		unicastMessageTopic,
		lsNodeMessageTopic,
		lsLinkMessageTopic,
		l3vpnMessageTopic,
		lsPrefixMessageTopic,
		lsSRv6SIDMessageTopic,
		evpnMessageTopic,
	}
)

// topicConnection defines per topic connection and connection related information
type topicConnection struct {
	kafkaConn  *kafka.Conn
	partitions []kafka.Partition
}

type publisher struct {
	sync.Mutex
	// topics is map of topics' connections, keyed by the topic name
	topics map[string]*topicConnection
}

func (p *publisher) PublishMessage(t int, key []byte, msg []byte) error {
	switch t {
	case bmp.PeerStateChangeMsg:
		return p.produceMessage(peerTopic, key, msg)
	case bmp.UnicastPrefixMsg:
		return p.produceMessage(unicastMessageTopic, key, msg)
	case bmp.LSNodeMsg:
		return p.produceMessage(lsNodeMessageTopic, key, msg)
	case bmp.LSLinkMsg:
		return p.produceMessage(lsLinkMessageTopic, key, msg)
	case bmp.L3VPNMsg:
		return p.produceMessage(l3vpnMessageTopic, key, msg)
	case bmp.LSPrefixMsg:
		return p.produceMessage(lsPrefixMessageTopic, key, msg)
	case bmp.LSSRv6SIDMsg:
		return p.produceMessage(lsSRv6SIDMessageTopic, key, msg)
	case bmp.EVPNMsg:
		return p.produceMessage(evpnMessageTopic, key, msg)
	}

	return fmt.Errorf("not implemented")
}

func (p *publisher) produceMessage(topic string, key []byte, msg []byte) error {
	p.Lock()
	defer p.Unlock()
	t, ok := p.topics[topic]
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
		Key:   key,
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

// NewKafkaPublisher instantiates a new instance of a Kafka publisher
func NewKafkaPublisher(kafkaSrv string) (pub.Publisher, error) {
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

	return &publisher{
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

		glog.V(5).Infof("Getting partitions for Kafka topic %s succeeded", t.Topic)

		leaderAddr := fmt.Sprintf("%s:%d", p[0].Leader.Host, p[0].Leader.Port)
		kafkaConn, err := kafka.DefaultDialer.DialLeader(context.TODO(), "tcp", leaderAddr, p[0].Topic, p[0].Leader.ID)
		if err != nil {
			return nil, err
		}
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
