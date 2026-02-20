package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/tools"
)

var (
	msgSrvAddr             string
	topicRetnTimeMs        string
	kafkaTopicPrefix       string
	kafkaSkipTopicCreation string
	kafkaSASLUser          string
	kafkaSASLPassword      string
	kafkaSASLMechanism     string
	kafkaTLS               string
	kafkaTLSSkipVerify     string
	kafkaTLSCAFile         string
	file                   string
	delay                  int
	iterations             int
)

func init() {
	flag.StringVar(&msgSrvAddr, "message-server", "", "URL to the messages supplying server")
	flag.StringVar(&topicRetnTimeMs, "topic-retention-time-ms", "900000", "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	flag.StringVar(&kafkaTopicPrefix, "kafka-topic-prefix", "", "Optional prefix prepended to all Kafka topic names (e.g. 'prod' -> 'prod.gobmp.parsed.peer')")
	flag.StringVar(&kafkaSkipTopicCreation, "kafka-skip-topic-creation", "false", "When true, do not create topics via Kafka Admin API (use with Kafka 4.0+)")
	flag.StringVar(&kafkaSASLUser, "kafka-sasl-username", "", "Kafka SASL username (enables SASL when set)")
	flag.StringVar(&kafkaSASLPassword, "kafka-sasl-password", "", "Kafka SASL password (required if kafka-sasl-username is set)")
	flag.StringVar(&kafkaSASLMechanism, "kafka-sasl-mechanism", "SCRAM-SHA-512", "SASL mechanism: SCRAM-SHA-512 or SCRAM-SHA-256")
	flag.StringVar(&kafkaTLS, "kafka-tls", "true", "Use TLS for Kafka")
	flag.StringVar(&kafkaTLSSkipVerify, "kafka-tls-skip-verify", "false", "Skip Kafka broker TLS cert and hostname verification (use if broker cert has no SANs; insecure)")
	flag.StringVar(&kafkaTLSCAFile, "kafka-tls-ca", "", "Path to CA certificate (PEM) for Kafka broker TLS verification")
	flag.StringVar(&file, "msg-file", "/tmp/messages.json", "File with the bmp messages to replay")
	flag.IntVar(&delay, "delay", 0, "Delay in seconds to add between sending messages")
	flag.IntVar(&iterations, "iterations", 1, "Number of iterations to replay messages")
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	glog.Infof("kafka server url: %s", msgSrvAddr)
	// Open messages file
	f, err := os.Open(file)
	if err != nil {
		glog.Errorf("fail to open messages file %s with error: %+v", file, err)
		os.Exit(1)
	}

	// Initializing publisher process
	skipTopicCreation, err := strconv.ParseBool(kafkaSkipTopicCreation)
	if err != nil {
		glog.Errorf("failed to parse kafka-skip-topic-creation %q: %+v", kafkaSkipTopicCreation, err)
		os.Exit(1)
	}
	useTLS, err := strconv.ParseBool(kafkaTLS)
	if err != nil {
		glog.Errorf("failed to parse kafka-tls %q: %+v", kafkaTLS, err)
		os.Exit(1)
	}
	tlsSkipVerify, err := strconv.ParseBool(kafkaTLSSkipVerify)
	if err != nil {
		glog.Errorf("failed to parse kafka-tls-skip-verify %q: %+v", kafkaTLSSkipVerify, err)
		os.Exit(1)
	}
	kConfig := &kafka.Config{
		ServerAddress:        msgSrvAddr,
		TopicRetentionTimeMs: topicRetnTimeMs,
		TopicPrefix:          kafkaTopicPrefix,
		SkipTopicCreation:    skipTopicCreation,
		SASLUser:             kafkaSASLUser,
		SASLPassword:         kafkaSASLPassword,
		SASLMechanism:        kafkaSASLMechanism,
		UseTLS:               useTLS,
		TLSSkipVerify:        tlsSkipVerify,
		TLSCAFilePath:        kafkaTLSCAFile,
	}
	publisher, err := kafka.NewKafkaPublisher(kConfig)
	if err != nil {
		glog.Errorf("fail to initialize Kafka publisher with error: %+v", err)
		os.Exit(1)
	}
	glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	defer publisher.Stop()

	msgs, err := loadMessages(f)
	if err != nil {
		glog.Errorf("Failed to load messages with error: %+v", err)
		os.Exit(1)
	}
	records := 0
	var wg sync.WaitGroup
	for i := 0; i < iterations; i++ {
		start := time.Now()
		for e := 0; e < len(msgs); e++ {
			wg.Add(1)
			go func(msg *filer.MsgOut) {
				defer wg.Done()
				if err := publisher.PublishMessage(msg.MsgType, []byte(msg.MsgHash), []byte(msg.Msg)); err != nil {
					glog.Errorf("fail to publish message type: %d message key: %s with error: %+v", msg.MsgType, tools.MessageHex([]byte(msg.MsgHash)), err)
				}
			}(msgs[e])
			records++
			// If delay was specified in the input parameters, wait for n-seconds before sending next message.
			time.Sleep(time.Second * time.Duration(delay))
		}
		wg.Wait()
		glog.Infof("%3f seconds took to process %d records", time.Since(start).Seconds(), records)
		records = 0
	}
	_ = f.Close()

	os.Exit(0)
}

func loadMessages(f *os.File) ([]*filer.MsgOut, error) {
	msgs := make([]*filer.MsgOut, 0)
	m := bufio.NewReader(f)
	done := false
	for !done {
		b, err := m.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				return nil, fmt.Errorf("fail to read messages file %s with error: %+v", file, err)
			}
			done = true
			continue
		}
		msg := &filer.MsgOut{}
		if err := json.Unmarshal(b, msg); err != nil {
			return nil, fmt.Errorf("fail to unmarshal message with error: %+v", err)
		}
		msgs = append(msgs, msg)
	}

	return msgs, nil
}
