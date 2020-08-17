package main

import (
	"bufio"
	"flag"
	"io"
	"os"

	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/tools"
)

var (
	msgSrvAddr string
	file       string
)

func init() {
	flag.StringVar(&msgSrvAddr, "message-server", "", "URL to the messages supplying server")
	flag.StringVar(&file, "msg-file", "/tmp/messages.json", "File with the bmp messages to replay")
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
	glog.V(6).Infof("Kafka publisher has been successfully initialized.")

	msgs := bufio.NewReader(f)
	done := false
	for !done {
		b, err := msgs.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				glog.Errorf("fail to read messages file %s with error: %+v", file, err)
				os.Exit(1)
			}
			done = true
			continue
		}
		msg := &filer.MsgOut{}
		if err := json.Unmarshal(b, msg); err != nil {
			glog.Errorf("fail to unmarshal message with error: %+v", err)
			os.Exit(1)
		}
		glog.Infof("Recovered message of type: %d", msg.Type)
		if err := publisher.PublishMessage(msg.Type, msg.Key, msg.Value); err != nil {
			glog.Errorf("fail to publish message type: %d message key: %s with error: %+v", msg.Type, tools.MessageHex(msg.Key), err)
			os.Exit(1)
		}
	}

	publisher.Stop()

	os.Exit(0)
}
