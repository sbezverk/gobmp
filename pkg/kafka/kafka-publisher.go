package kafka

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/Shopify/sarama"
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// Define constants for each topic name
const (
	peerTopic              = "gobmp.parsed.peer"
	unicastMessageTopic    = "gobmp.parsed.unicast_prefix"
	unicastMessageV4Topic  = "gobmp.parsed.unicast_prefix_v4"
	unicastMessageV6Topic  = "gobmp.parsed.unicast_prefix_v6"
	lsNodeMessageTopic     = "gobmp.parsed.ls_node"
	lsLinkMessageTopic     = "gobmp.parsed.ls_link"
	l3vpnMessageTopic      = "gobmp.parsed.l3vpn"
	l3vpnMessageV4Topic    = "gobmp.parsed.l3vpn_v4"
	l3vpnMessageV6Topic    = "gobmp.parsed.l3vpn_v6"
	lsPrefixMessageTopic   = "gobmp.parsed.ls_prefix"
	lsSRv6SIDMessageTopic  = "gobmp.parsed.ls_srv6_sid"
	evpnMessageTopic       = "gobmp.parsed.evpn"
	srPolicyMessageTopic   = "gobmp.parsed.sr_policy"
	srPolicyMessageV4Topic = "gobmp.parsed.sr_policy_v4"
	srPolicyMessageV6Topic = "gobmp.parsed.sr_policy_v6"
	flowspecMessageTopic   = "gobmp.parsed.flowspec"
	flowspecMessageV4Topic = "gobmp.parsed.flowspec_v4"
	flowspecMessageV6Topic = "gobmp.parsed.flowspec_v6"
	statsMessageTopic      = "gobmp.parsed.statistics"
)

var (
	brockerConnectTimeout = 120 * time.Second
	topicCreateTimeout    = 1 * time.Second
	// goBMP topic's retention timer is 15 minutes
	topicRetention = "900000"
)

var (
	// topics defines a list of topic to initialize and connect,
	// initialization is done as a part of NewKafkaPublisher func.
	topicNames = []string{
		peerTopic,
		unicastMessageTopic,
		unicastMessageV4Topic,
		unicastMessageV6Topic,
		lsNodeMessageTopic,
		lsLinkMessageTopic,
		l3vpnMessageTopic,
		l3vpnMessageV4Topic,
		l3vpnMessageV6Topic,
		lsPrefixMessageTopic,
		lsSRv6SIDMessageTopic,
		evpnMessageTopic,
		srPolicyMessageTopic,
		srPolicyMessageV4Topic,
		srPolicyMessageV6Topic,
		flowspecMessageTopic,
		flowspecMessageV4Topic,
		flowspecMessageV6Topic,
		statsMessageTopic,
	}
)

type publisher struct {
	broker   *sarama.Broker
	config   *sarama.Config
	producer sarama.AsyncProducer
	stopCh   chan struct{}
}

func (p *publisher) PublishMessage(t int, key []byte, msg []byte) error {
	switch t {
	case bmp.PeerStateChangeMsg:
		return p.produceMessage(peerTopic, key, msg)
	case bmp.UnicastPrefixMsg:
		return p.produceMessage(unicastMessageTopic, key, msg)
	case bmp.UnicastPrefixV4Msg:
		return p.produceMessage(unicastMessageV4Topic, key, msg)
	case bmp.UnicastPrefixV6Msg:
		return p.produceMessage(unicastMessageV6Topic, key, msg)
	case bmp.LSNodeMsg:
		return p.produceMessage(lsNodeMessageTopic, key, msg)
	case bmp.LSLinkMsg:
		return p.produceMessage(lsLinkMessageTopic, key, msg)
	case bmp.L3VPNMsg:
		return p.produceMessage(l3vpnMessageTopic, key, msg)
	case bmp.L3VPNV4Msg:
		return p.produceMessage(l3vpnMessageV4Topic, key, msg)
	case bmp.L3VPNV6Msg:
		return p.produceMessage(l3vpnMessageV6Topic, key, msg)
	case bmp.LSPrefixMsg:
		return p.produceMessage(lsPrefixMessageTopic, key, msg)
	case bmp.LSSRv6SIDMsg:
		return p.produceMessage(lsSRv6SIDMessageTopic, key, msg)
	case bmp.EVPNMsg:
		return p.produceMessage(evpnMessageTopic, key, msg)
	case bmp.SRPolicyMsg:
		return p.produceMessage(srPolicyMessageTopic, key, msg)
	case bmp.SRPolicyV4Msg:
		return p.produceMessage(srPolicyMessageV4Topic, key, msg)
	case bmp.SRPolicyV6Msg:
		return p.produceMessage(srPolicyMessageV6Topic, key, msg)
	case bmp.FlowspecMsg:
		return p.produceMessage(flowspecMessageTopic, key, msg)
	case bmp.FlowspecV4Msg:
		return p.produceMessage(flowspecMessageV4Topic, key, msg)
	case bmp.FlowspecV6Msg:
		return p.produceMessage(flowspecMessageV6Topic, key, msg)
	case bmp.StatsReportMsg:
		return p.produceMessage(statsMessageTopic, key, msg)
	}

	return fmt.Errorf("not implemented")
}

func (p *publisher) produceMessage(topic string, key []byte, msg []byte) error {
	var k sarama.ByteEncoder
	var m sarama.ByteEncoder
	k = key
	m = msg
	p.producer.Input() <- &sarama.ProducerMessage{
		Topic: topic,
		Key:   k,
		Value: m,
	}

	return nil
}

func (p *publisher) Stop() {
	close(p.stopCh)
	p.broker.Close()
}

// NewKafkaPublisher instantiates a new instance of a Kafka publisher
func NewKafkaPublisher(kafkaSrv string) (pub.Publisher, error) {
	glog.Infof("Initializing Kafka producer client")
	if err := validator(kafkaSrv); err != nil {
		glog.Errorf("Failed to validate Kafka server address %s with error: %+v", kafkaSrv, err)
		return nil, err
	}
	config := sarama.NewConfig()
	config.ClientID = "gobmp-producer" + "_" + strconv.Itoa(rand.Intn(1000))
	config.Producer.Return.Successes = true
	config.Version = sarama.V0_11_0_0

	br := sarama.NewBroker(kafkaSrv)
	if err := br.Open(config); err != nil {
		if err != sarama.ErrAlreadyConnected {
			return nil, err
		}
	}
	if err := waitForBrokerConnection(br, brockerConnectTimeout); err != nil {
		glog.Errorf("failed to open connection to the broker with error: %+v\n", err)
		return nil, err
	}
	glog.V(5).Infof("Connected to broker: %s id: %d\n", br.Addr(), br.ID())

	for _, t := range topicNames {
		if err := ensureTopic(br, topicCreateTimeout, t); err != nil {
			glog.Errorf("New Kafka publisher failed to ensure requested topics with error: %+v", err)
			return nil, err
		}
	}
	producer, err := sarama.NewAsyncProducer([]string{kafkaSrv}, config)
	if err != nil {
		glog.Errorf("New Kafka publisher failed to start new async producer with error: %+v", err)
		return nil, err
	}
	glog.V(5).Infof("Initialized Kafka Async producer")
	stopCh := make(chan struct{})
	go func(producer sarama.AsyncProducer, stopCh <-chan struct{}) {
		for {
			select {
			case <-producer.Successes():
			case err := <-producer.Errors():
				glog.Errorf("failed to produce message with error: %+v", *err)
			case <-stopCh:
				producer.Close()
				return
			}
		}
	}(producer, stopCh)

	return &publisher{
		stopCh:   stopCh,
		broker:   br,
		config:   config,
		producer: producer,
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

func ensureTopic(br *sarama.Broker, timeout time.Duration, topicName string) error {
	topic := &sarama.CreateTopicsRequest{
		TopicDetails: map[string]*sarama.TopicDetail{
			topicName: {
				NumPartitions:     1,
				ReplicationFactor: 1,
				ConfigEntries: map[string]*string{
					"retention.ms": &topicRetention,
				},
			},
		},
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	tout := time.NewTimer(timeout)
	for {
		t, err := br.CreateTopics(topic)
		if err != nil {
			return err
		}
		if e, ok := t.TopicErrors[topicName]; ok {
			if e.Err == sarama.ErrTopicAlreadyExists || e.Err == sarama.ErrNoError {
				return nil
			}
			if e.Err != sarama.ErrRequestTimedOut {
				return e
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-tout.C:
			return fmt.Errorf("timeout waiting for topic %s", topicName)
		}
	}
}

func waitForBrokerConnection(br *sarama.Broker, timeout time.Duration) error {
	ticker := time.NewTicker(10 * time.Second)
	tout := time.NewTimer(timeout)
	defer func() {
		ticker.Stop()
		tout.Stop()
	}()
	for {
		if ok, err := br.Connected(); err != nil {
			glog.Errorf("failed to connect to the broker with error: %+v, will retry in 10 seconds", err)
		} else {
			if ok {
				return nil
			} else {
				glog.Errorf("kafka broker %s is not ready yet, will retry in 10 seconds", br.Addr())
			}
		}
		select {
		case <-ticker.C:
			continue
		case <-tout.C:
			return fmt.Errorf("timeout waiting for the connection to the broker %s", br.Addr())
		}
	}

}
