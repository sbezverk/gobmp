package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/tools"
)

var (
	msgSrvAddr string
	file       string
	delay      int
	iterations int
)

func init() {
	flag.StringVar(&msgSrvAddr, "message-server", "", "URL to the messages supplying server")
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
	defer f.Close()

	// Initializing publisher process
	publisher, err := kafka.NewKafkaPublisher(msgSrvAddr)
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
				if err := publisher.PublishMessage(msg.Type, msg.Key, msg.Value); err != nil {
					glog.Errorf("fail to publish message type: %d message key: %s with error: %+v", msg.Type, tools.MessageHex(msg.Key), err)
				}
			}(msgs[e])
			records++
			// If delay was specified in the input parameters, wait for n-seconds before sending next message.
			time.Sleep(time.Second * time.Duration(delay))
		}
		wg.Wait()
		glog.Infof("%3f seconds took to process %d records", time.Now().Sub(start).Seconds(), records)
		records = 0
	}

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
