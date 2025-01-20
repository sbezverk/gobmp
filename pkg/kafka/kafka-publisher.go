package kafka

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/IBM/sarama"
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// Define constants for each topic name
const (
	PeerTopic              = "gobmp.parsed.peer"
	UnicastMessageTopic    = "gobmp.parsed.unicast_prefix"
	UnicastMessageV4Topic  = "gobmp.parsed.unicast_prefix_v4"
	UnicastMessageV6Topic  = "gobmp.parsed.unicast_prefix_v6"
	LSNodeMessageTopic     = "gobmp.parsed.ls_node"
	LSLinkMessageTopic     = "gobmp.parsed.ls_link"
	L3vpnMessageTopic      = "gobmp.parsed.l3vpn"
	L3vpnMessageV4Topic    = "gobmp.parsed.l3vpn_v4"
	L3vpnMessageV6Topic    = "gobmp.parsed.l3vpn_v6"
	LSPrefixMessageTopic   = "gobmp.parsed.ls_prefix"
	LSSRv6SIDMessageTopic  = "gobmp.parsed.ls_srv6_sid"
	EVPNMessageTopic       = "gobmp.parsed.evpn"
	SRPolicyMessageTopic   = "gobmp.parsed.sr_policy"
	SRPolicyMessageV4Topic = "gobmp.parsed.sr_policy_v4"
	SRPolicyMessageV6Topic = "gobmp.parsed.sr_policy_v6"
	FlowspecMessageTopic   = "gobmp.parsed.flowspec"
	FlowspecMessageV4Topic = "gobmp.parsed.flowspec_v4"
	FlowspecMessageV6Topic = "gobmp.parsed.flowspec_v6"
	StatsMessageTopic      = "gobmp.parsed.statistics"
)

var (
	brockerConnectTimeout = 120 * time.Second
	topicCreateTimeout    = 1 * time.Second
)

var (
	// topics defines a list of topic to initialize and connect,
	// initialization is done as a part of NewKafkaPublisher func.
	topicNames = []string{
		PeerTopic,
		UnicastMessageTopic,
		UnicastMessageV4Topic,
		UnicastMessageV6Topic,
		LSNodeMessageTopic,
		LSLinkMessageTopic,
		L3vpnMessageTopic,
		L3vpnMessageV4Topic,
		L3vpnMessageV6Topic,
		LSPrefixMessageTopic,
		LSSRv6SIDMessageTopic,
		EVPNMessageTopic,
		SRPolicyMessageTopic,
		SRPolicyMessageV4Topic,
		SRPolicyMessageV6Topic,
		FlowspecMessageTopic,
		FlowspecMessageV4Topic,
		FlowspecMessageV6Topic,
		StatsMessageTopic,
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
		return p.produceMessage(PeerTopic, key, msg)
	case bmp.UnicastPrefixMsg:
		return p.produceMessage(UnicastMessageTopic, key, msg)
	case bmp.UnicastPrefixV4Msg:
		return p.produceMessage(UnicastMessageV4Topic, key, msg)
	case bmp.UnicastPrefixV6Msg:
		return p.produceMessage(UnicastMessageV6Topic, key, msg)
	case bmp.LSNodeMsg:
		return p.produceMessage(LSNodeMessageTopic, key, msg)
	case bmp.LSLinkMsg:
		return p.produceMessage(LSLinkMessageTopic, key, msg)
	case bmp.L3VPNMsg:
		return p.produceMessage(L3vpnMessageTopic, key, msg)
	case bmp.L3VPNV4Msg:
		return p.produceMessage(L3vpnMessageV4Topic, key, msg)
	case bmp.L3VPNV6Msg:
		return p.produceMessage(L3vpnMessageV6Topic, key, msg)
	case bmp.LSPrefixMsg:
		return p.produceMessage(LSPrefixMessageTopic, key, msg)
	case bmp.LSSRv6SIDMsg:
		return p.produceMessage(LSSRv6SIDMessageTopic, key, msg)
	case bmp.EVPNMsg:
		return p.produceMessage(EVPNMessageTopic, key, msg)
	case bmp.SRPolicyMsg:
		return p.produceMessage(SRPolicyMessageTopic, key, msg)
	case bmp.SRPolicyV4Msg:
		return p.produceMessage(SRPolicyMessageV4Topic, key, msg)
	case bmp.SRPolicyV6Msg:
		return p.produceMessage(SRPolicyMessageV6Topic, key, msg)
	case bmp.FlowspecMsg:
		return p.produceMessage(FlowspecMessageTopic, key, msg)
	case bmp.FlowspecV4Msg:
		return p.produceMessage(FlowspecMessageV4Topic, key, msg)
	case bmp.FlowspecV6Msg:
		return p.produceMessage(FlowspecMessageV6Topic, key, msg)
	case bmp.StatsReportMsg:
		return p.produceMessage(StatsMessageTopic, key, msg)
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
func NewKafkaPublisher(kConfig *Config) (pub.Publisher, error) {
	glog.Infof("Initializing Kafka producer client")
	if err := validator(kConfig); err != nil {
		glog.Errorf("Failed to validate Kafka config: %v with error: %+v", kConfig, err)
		return nil, err
	}
	if glog.V(6) {
		sarama.Logger = log.New(os.Stdout, "[sarama]      ", log.LstdFlags)
	}
	config := sarama.NewConfig()
	config.ClientID = "gobmp-producer" + "_" + strconv.Itoa(rand.Intn(1000))
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Admin.Retry.Max = 100
	config.Version = sarama.V1_1_0_0

	br := sarama.NewBroker(kConfig.ServerAddress)

	if err := waitForBrokerConnection(br, config, brockerConnectTimeout); err != nil {
		glog.Errorf("failed to open connection to the broker with error: %+v\n", err)
		return nil, err
	}
	glog.V(5).Infof("Connected to broker: %s id: %d\n", br.Addr(), br.ID())

	for _, t := range topicNames {
		if err := ensureTopic(br, topicCreateTimeout, t, kConfig); err != nil {
			glog.Errorf("New Kafka publisher failed to ensure requested topics with error: %+v", err)
			return nil, err
		}
	}
	producer, err := sarama.NewAsyncProducer([]string{kConfig.ServerAddress}, config)
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

func validator(kConfig *Config) error {
	if kConfig == nil {
		return fmt.Errorf("kafka config can not be nil")
	}
	host, port, _ := net.SplitHostPort(kConfig.ServerAddress)
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
	// validator for topic retention time
	i, err := strconv.Atoi(kConfig.TopicRetentionTimeMs)
	if err != nil {
		return err
	}
	if i < -1 {
		return fmt.Errorf("kafka topic retention time can not be less than 0")
	}
	return nil
}

func ensureTopic(br *sarama.Broker, timeout time.Duration, topicName string, kConfig *Config) error {
	topic := &sarama.CreateTopicsRequest{
		TopicDetails: map[string]*sarama.TopicDetail{
			topicName: {
				NumPartitions:     1,
				ReplicationFactor: 1,
				ConfigEntries: map[string]*string{
					"retention.ms": &kConfig.TopicRetentionTimeMs,
				},
			},
		},
		Timeout: timeout,
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

func waitForBrokerConnection(br *sarama.Broker, config *sarama.Config, timeout time.Duration) error {
	ticker := time.NewTicker(10 * time.Second)
	tout := time.NewTimer(timeout)
	defer func() {
		ticker.Stop()
		tout.Stop()
	}()
	for {
		if err := br.Open(config); err == nil {
			if ok, err := br.Connected(); err != nil {
				glog.Errorf("failed to connect to the broker with error: %+v, will retry in 10 seconds", err)
			} else {
				if ok {
					return nil
				} else {
					glog.Errorf("kafka broker %s is not ready yet, will retry in 10 seconds", br.Addr())
				}
			}
		} else {
			if err == sarama.ErrAlreadyConnected {
				return nil
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
