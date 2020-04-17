package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"net/http"
	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/kafka"
)

var (
	dstPort   int
	srcPort   int
	perfPort  int
	kafkaSrv  string
	intercept bool
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.BoolVar(&intercept, "intercept", false, "Mode of operation, in intercept mode, when intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	flag.IntVar(&perfPort, "performance-port", 56767, "port used for performance debugging")
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
	// Initializing Kafka publisher
	// other publishers sutisfying pub.Publisher interface can be used.
	go func() {
		glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", perfPort), nil))
	}()

	publisher, err := kafka.NewKafkaPublisher(kafkaSrv)
	if err != nil {
		glog.Warningf("Kafka publisher is disabled, no Kafka server URL is provided.")
	} else {
		glog.V(6).Infof("Kafka publisher has been successfully initialized.")
	}
	// Initializing bmp server
	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, intercept, publisher)
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
