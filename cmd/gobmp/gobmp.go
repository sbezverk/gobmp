package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"net/http"
	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/dumper"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/pub"
)

var (
	dstPort   int
	srcPort   int
	perfPort  int
	kafkaSrv  string
	intercept string
	splitAF   string
	dump      string
	file      string
)

func init() {
	runtime.GOMAXPROCS(1)
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&intercept, "intercept", "false", "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	flag.StringVar(&splitAF, "split-af", "true", "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 56767, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\" or to the standard output when \"dump=console\"")
	flag.StringVar(&file, "msg-file", "/tmp/messages.json", "Full path anf file name to store messages when \"dump=file\"")
}

var (
	shutdownSignals = []os.Signal{os.Interrupt}
)

func setupSignalHandler() (stopCh <-chan struct{}) {
	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 0)
	signal.Notify(sigCh, shutdownSignals...)
	go func() {
		<-sigCh
		close(stop)
	}()

	return stop
}

func main() {
	flag.Parse()
	flag.Set("logtostderr", "true")
	// Starting performance collecting http server
	go func() {
		glog.Info(http.ListenAndServe(net.JoinHostPort("", strconv.Itoa(perfPort)), nil))
	}()

	// Initializing publisher
	var publisher pub.Publisher
	var err error
	switch strings.ToLower(dump) {
	case "file":
		publisher, err = filer.NewFiler(file)
		if err != nil {
			glog.Errorf("failed to initialize file publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("file publisher has been successfully initialized.")
	case "console":
		publisher, err = dumper.NewDumper()
		if err != nil {
			glog.Errorf("failed to initialize console publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("console publisher has been successfully initialized.")
	default:
		publisher, err = kafka.NewKafkaPublisher(kafkaSrv)
		if err != nil {
			glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	}

	// Initializing bmp server
	interceptFlag, err := strconv.ParseBool(intercept)
	if err != nil {
		glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
		os.Exit(1)
	}
	splitAFFlag, err := strconv.ParseBool(splitAF)
	if err != nil {
		glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
		os.Exit(1)
	}
	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, interceptFlag, publisher, splitAFFlag)
	if err != nil {
		glog.Errorf("failed to setup new gobmp server with error: %+v", err)
		os.Exit(1)
	}
	bmpSrv.Start()

	stopCh := setupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
}
