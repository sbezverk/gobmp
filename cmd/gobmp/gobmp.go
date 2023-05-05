package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"net/http"
	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/dumper"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/pub"
	"github.com/sbezverk/tools"
)

var (
	srcPort   = flag.Int("source-port", 5000, "port exposed to outside")
	dstPort   = flag.Int("destination-port", 5050, "port openBMP is listening")
	kafkaSrv  = flag.String("kafka-server", "", "URL to access Kafka server")
	intercept = flag.Bool("intercept", false, "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	splitAF   = flag.Bool("split-af", true, "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	perfPort  = flag.Int("performance-port", 56767, "port used for performance debugging")
	dump      = flag.String("dump", "", "Dump resulting messages to file when \"dump=file\" or to the standard output when \"dump=console\"")
	file      = flag.String("msg-file", "/tmp/messages.json", "Full path anf file name to store messages when \"dump=file\"")
)

func init() {
	runtime.GOMAXPROCS(1)
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	// Starting performance collecting http server
	go func() {
		glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", perfPort), nil))
	}()
	// Initializing publisher
	var publisher pub.Publisher
	var err error
	switch strings.ToLower(*dump) {
	case "file":
		publisher, err = filer.NewFiler(*file)
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
		publisher, err = kafka.NewKafkaPublisher(*kafkaSrv)
		if err != nil {
			glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	}

	// Initializing bmp server
	bmpSrv, err := gobmpsrv.NewBMPServer(*srcPort, *dstPort, *intercept, publisher, *splitAF)
	if err != nil {
		glog.Errorf("failed to setup new gobmp server with error: %+v", err)
		os.Exit(1)
	}
	// Starting Interceptor server
	bmpSrv.Start()

	stopCh := tools.SetupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
	os.Exit(0)
}
