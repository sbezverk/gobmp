package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/validator"
)

var (
	msgSrvAddr    string
	msgFile       string
	validatorFlag bool
	testCase      string
	timeout       int
)

func init() {
	flag.StringVar(&msgSrvAddr, "kafka", "kafka:9092", "kafka server url, default: kafka:9092")
	flag.StringVar(&msgFile, "msg-file", "./messages.json", "file to read from or to store to processed bmp messages")
	flag.IntVar(&timeout, "timeout", 300, "timeout in seconds, default 300, for the test to complete all processing.")
	flag.BoolVar(&validatorFlag, "validate", false, "when validator is true, incomming messages are validated against stored in the message file, otherwise the messages are stored in the file.")
	flag.StringVar(&testCase, "test-case", "u4", "test case to validate or to collect messages")
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	var f *os.File
	var err error
	var b []byte
	if validatorFlag {
		// validator will receive messages from kafka and compare with messages stored in the message file\
		if f, err = os.Open(msgFile); err != nil {
			glog.Errorf("failed to open message file: %s with error: %+v", msgFile, err)
			os.Exit(1)
		}
		if b, err = io.ReadAll(f); err != nil {
			glog.Errorf("failed to read message file: %s with error: %+v", msgFile, err)
			os.Exit(1)
		}
	} else {
		if f, err = os.Create(msgFile); err != nil {
			glog.Errorf("failed to create message file: %s with error: %+v", msgFile, err)
			os.Exit(1)
		}
	}
	// If this point is reached f cannot be nil
	defer f.Close()
	errCh := make(chan error)
	stopCh := make(chan struct{})

	topics := make([]*kafka.TopicDescriptor, 0)
	tests := strings.Split(testCase, ",")
	for _, test := range tests {
		switch test {
		case "u4":
			topics = append(topics, &kafka.TopicDescriptor{
				TopicName: kafka.UnicastMessageV4Topic,
				TopicType: bmp.UnicastPrefixV4Msg,
				TopicChan: make(chan []byte),
			})
		default:
			glog.Errorf("Unsupported or invalid test case %s", test)
			os.Exit(1)
		}
	}
	// Starting Check and Store depending on the validator Flag

	if validatorFlag {
		go validator.Check(topics, b, errCh)
	} else {
		go validator.Store(topics, f, stopCh, errCh)
	}

	// Setting up timeout and wait either on a timeout or result from errCh
	timeOut := time.NewTimer(time.Second * time.Duration(timeout))
	select {
	case <-timeOut.C:
		close(stopCh)
		if validatorFlag {
			glog.Errorf("timed out waiting for the test to complete")
			os.Exit(1)
		}
	case err := <-errCh:
		close(stopCh)
		if err != nil {
			glog.Errorf("validation failed with error: %+v", err)
			os.Exit(1)
		} else {
			glog.Infof("validation succeeded")
			os.Exit(0)
		}
	}

	os.Exit(0)
}
