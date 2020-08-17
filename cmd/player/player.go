package main

import (
	"flag"
	"os"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/kafka"
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

	// Open messages file
	f, err := os.Open(file)
	if err != nil {
		glog.Errorf("fail to open messages file %s with error: %+v", file, err)
		os.Exit(1)
	}
	// Initializing publisher process
	publisher, err := kafka.NewKafkaPublisher(msgSrvAddr)
	if err != nil {
		glog.Errorf("fail to initialize Kafka publisher with error: %+v", err)
		os.Exit(1)
	}
	glog.V(6).Infof("Kafka publisher has been successfully initialized.")

	os.Exit(0)
}
