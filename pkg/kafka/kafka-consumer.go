package kafka

import (
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IBM/sarama"
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// Srv defines required method of a processor server.
type Srv interface {
	Start()
	Stop()
}

type TopicDescriptor struct {
	TopicName string
	TopicType int
	TopicChan chan []byte
}

type kafka struct {
	stopCh  chan struct{}
	readers sync.WaitGroup
	topics  []*TopicDescriptor
	config  *sarama.Config
	master  sarama.Consumer
}

// NewKafkaMessenger returns an instance of a kafka consumer acting as a messenger server.
func NewKafkaMConsumer(kafkaSrv string, topics []*TopicDescriptor) (Srv, error) {
	glog.Infof("NewKafkaConsumer")

	config := sarama.NewConfig()
	config.ClientID = "validator" + "_" + strconv.Itoa(rand.Intn(1000))
	config.Consumer.Return.Errors = true
	config.Version = sarama.V3_0_0_0

	brokers := strings.Split(kafkaSrv, ",")
	for _, broker := range brokers {
		if err := tools.HostAddrValidator(broker); err != nil {
			return nil, err
		}
	}
	// Create new consumer
	master, err := sarama.NewConsumer(brokers, config)
	if err != nil {
		return nil, err
	}
	k := &kafka{
		stopCh: make(chan struct{}),
		config: config,
		master: master,
		topics: topics,
	}

	return k, nil
}

func (k *kafka) Start() {
	// Starting readers for each topic name and type defined in topics map
	for _, topic := range k.topics {
		k.readers.Add(1)
		go func() {
			defer k.readers.Done()
			k.topicReader(topic)
		}()
	}
}

func (k *kafka) Stop() {
	close(k.stopCh)
	k.readers.Wait()
	if err := k.master.Close(); err != nil {
		glog.Errorf("failed to close Kafka consumer: %v", err)
	}
}

func (k *kafka) topicReader(topic *TopicDescriptor) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-k.stopCh:
			return
		default:
		}
		// Loop until either a topic becomes available at the broker or stop signal is received
		partitions, err := k.master.Partitions(topic.TopicName)
		if nil != err {
			glog.Errorf("fail to get partitions for the topic %s with error: %+v", topic.TopicName, err)
			select {
			case <-ticker.C:
			case <-k.stopCh:
				return
			}
			continue
		}
		// Loop until either a topic's partition becomes consumable or stop signal is received
		consumer, err := k.master.ConsumePartition(topic.TopicName, partitions[0], sarama.OffsetOldest)
		if nil != err {
			glog.Errorf("fail to consume partition for the topic %s with error: %+v", topic.TopicName, err)
			select {
			case <-ticker.C:
			case <-k.stopCh:
				return
			}
			continue
		}
		defer func() {
			if err := consumer.Close(); err != nil {
				glog.Errorf("failed to close Kafka partition %s/%d: %v", topic.TopicName, partitions[0], err)
			}
		}()
		glog.Infof("Starting Kafka reader for topic: %s", topic.TopicName)
		messages, consumerErrors := consumer.Messages(), consumer.Errors()
		for {
			select {
			case msg, ok := <-messages:
				if !ok {
					return
				}
				if msg == nil {
					continue
				}
				select {
				case topic.TopicChan <- msg.Value:
				case <-k.stopCh:
					return
				}
			case consumerError, ok := <-consumerErrors:
				if !ok {
					consumerErrors = nil
					continue
				}
				if consumerError == nil {
					continue
				}
				glog.Errorf("error %+v for topic: %s, partition: %d", consumerError.Err, consumerError.Topic, consumerError.Partition)
			case <-k.stopCh:
				return
			}
		}
	}
}
