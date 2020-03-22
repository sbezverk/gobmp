package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	kafka "github.com/sbezverk/gobmp/pkg/kafkaproducer"
)

var (
	dstPort   int
	srcPort   int
	kafkaSrv  string
	intercept bool
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.BoolVar(&intercept, "intercept", false, "Mode of operation, in intercept mode, when intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
}

var (
	onlyOneSignalHandler = make(chan struct{})
	shutdownSignals      = []os.Signal{os.Interrupt}
)

func setupSignalHandler() (stopCh <-chan struct{}) {
	close(onlyOneSignalHandler) // panics when called twice

	stop := make(chan struct{})
	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		<-c
		close(stop)
		<-c
		os.Exit(1) // second signal. Exit directly.
	}()

	return stop
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	// Initializing Kafka producer
	kp, err := kafka.NewKafkaProducerClient(kafkaSrv)
	if err != nil {
		glog.Warningf("Kafka producer is disabled, no Kafka server URL is provided.")
	} else {
		glog.V(6).Infof("Kafka producer was initialized: %+v", kp)
	}
	// Initializing bmp server
	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, intercept, kp)
	if err != nil {
		glog.Errorf("fail to setup new bmp server with error: %+v", err)
		os.Exit(1)
	}
	// Starting Interceptor server
	bmpSrv.Start()

	stopCh := setupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
	os.Exit(0)
}
