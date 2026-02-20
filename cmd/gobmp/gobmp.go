package main

import (
	"flag"
	"fmt"
	"os"
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
	"github.com/sbezverk/gobmp/pkg/nats"
	"github.com/sbezverk/gobmp/pkg/pub"
	"github.com/sbezverk/tools"
)

var (
	dstPort                int
	srcPort                int
	perfPort               int
	kafkaSrv               string
	kafkaTpRetnTimeMs      string
	kafkaTopicPrefix       string
	kafkaSkipTopicCreation string
	kafkaSASLUser          string
	kafkaSASLPassword      string
	kafkaSASLMechanism     string
	kafkaTLS               string
	kafkaTLSSkipVerify     string
	kafkaTLSCAFile         string
	natsSrv                string
	intercept              string
	splitAF                string
	dump                   string
	file                   string
	bmpRaw                 string
	adminID                string
)

func init() {
	runtime.GOMAXPROCS(1)
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&kafkaTpRetnTimeMs, "kafka-topic-retention-time-ms", "900000", "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	flag.StringVar(&kafkaTopicPrefix, "kafka-topic-prefix", "", "Optional prefix prepended to all Kafka topic names (e.g. 'prod' -> 'prod.gobmp.parsed.peer')")
	flag.StringVar(&kafkaSkipTopicCreation, "kafka-skip-topic-creation", "false", "When true, do not create topics via Kafka Admin API (use with Kafka 4.0+ or when topics are pre-created)")
	flag.StringVar(&kafkaSASLUser, "kafka-sasl-username", "", "Kafka SASL username (enables SASL when set)")
	flag.StringVar(&kafkaSASLPassword, "kafka-sasl-password", "", "Kafka SASL password (required if kafka-sasl-username is set)")
	flag.StringVar(&kafkaSASLMechanism, "kafka-sasl-mechanism", "SCRAM-SHA-512", "SASL mechanism: SCRAM-SHA-512 or SCRAM-SHA-256")
	flag.StringVar(&kafkaTLS, "kafka-tls", "true", "Use TLS for Kafka (default true when SASL is used; set false for SASL_PLAINTEXT)")
	flag.StringVar(&kafkaTLSSkipVerify, "kafka-tls-skip-verify", "false", "Skip Kafka broker TLS cert and hostname verification (use if broker cert has no SANs; insecure)")
	flag.StringVar(&kafkaTLSCAFile, "kafka-tls-ca", "", "Path to CA certificate (PEM) for Kafka broker TLS verification")
	flag.StringVar(&natsSrv, "nats-server", "", "URL to access NATS server")
	flag.StringVar(&intercept, "intercept", "false", "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	flag.StringVar(&splitAF, "split-af", "true", "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 56767, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\", to standard output when \"dump=console\" or to NATS when \"dump=nats\"")
	flag.StringVar(&file, "msg-file", "/tmp/messages.json", "Full path anf file name to store messages when \"dump=file\"")
	flag.StringVar(&bmpRaw, "bmp-raw", "false", "When set \"true\", BMP messages are published in RAW format without parsing (OpenBMP compatibility mode)")
	flag.StringVar(&adminID, "admin-id", "", "Collector admin ID for RAW messages (defaults to hostname). Used to generate collector hash for OpenBMP compatibility")
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
	case "nats":
		publisher, err = nats.NewPublisher(natsSrv)
		if err != nil {
			glog.Errorf("failed to initialize NATS publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("NATS publisher has been successfully initialized.")
	default:
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
			ServerAddress:       kafkaSrv,
			TopicRetentionTimeMs: kafkaTpRetnTimeMs,
			TopicPrefix:          kafkaTopicPrefix,
			SkipTopicCreation:   skipTopicCreation,
			SASLUser:            kafkaSASLUser,
			SASLPassword:        kafkaSASLPassword,
			SASLMechanism:       kafkaSASLMechanism,
			UseTLS:              useTLS,
			TLSSkipVerify:       tlsSkipVerify,
			TLSCAFilePath:       kafkaTLSCAFile,
		}
		publisher, err = kafka.NewKafkaPublisher(kConfig)
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
	bmpRawFlag, err := strconv.ParseBool(bmpRaw)
	if err != nil {
		glog.Errorf("failed to parse to bool the value of the bmp-raw flag with error: %+v", err)
		os.Exit(1)
	}

	// Set default admin ID to hostname if not provided
	collectorAdminID := adminID
	if collectorAdminID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			glog.Warningf("failed to get hostname, using 'gobmp-collector' as admin ID: %+v", err)
			collectorAdminID = "gobmp-collector"
		} else {
			collectorAdminID = hostname
		}
	}

	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, interceptFlag, publisher, splitAFFlag, bmpRawFlag, collectorAdminID)
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
