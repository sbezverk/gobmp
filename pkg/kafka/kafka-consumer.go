package kafka

import (
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// Srv defines required method of a processor server
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
	stopCh chan struct{}
	topics []*TopicDescriptor
	config *sarama.Config
	master sarama.Consumer
}

// NewKafkaMessenger returns an instance of a kafka consumer acting as a messenger server
func NewKafkaMConsumer(kafkaSrv string, topics []*TopicDescriptor) (Srv, error) {
	glog.Infof("NewKafkaConsumer")
	brokers := strings.Split(kafkaSrv, ",")
	for i := range brokers {
		if err := tools.HostAddrValidator(brokers[i]); err != nil {
			return nil, err
		}
	}

	config := sarama.NewConfig()
	config.ClientID = "validator" + "_" + strconv.Itoa(rand.Intn(1000))
	config.Consumer.Return.Errors = true
	config.Version = sarama.V1_1_0_0

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
		go k.topicReader(topic)
	}
}

func (k *kafka) Stop() {
	close(k.stopCh)
	k.master.Close()
}

func (k *kafka) topicReader(topic *TopicDescriptor) {
	ticker := time.NewTicker(200 * time.Millisecond)
	for {
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
		glog.Infof("Starting Kafka reader for topic: %s", topic.TopicName)
		for {
			select {
			case msg := <-consumer.Messages():
				if msg == nil {
					continue
				}
				go func() {
					topic.TopicChan <- msg.Value
				}()
			case consumerError := <-consumer.Errors():
				if consumerError == nil {
					break
				}
				glog.Errorf("error %+v for topic: %s, partition: %s ", consumerError.Err, string(consumerError.Topic), string(consumerError.Partition))
			case <-k.stopCh:
				return
			}
		}
	}
}
