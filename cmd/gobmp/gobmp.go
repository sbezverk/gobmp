package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
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
	dstPort        int
	srcPort        int
	perfPort       int
	kafkaSrv       string
	intercept      string
	splitAF        string
	dump           string
	file           string
	configFilePath string
)

var defaultTopicsConfig = kafka.TopicsConfig{
	UnicastIPv4Topic:  "gobmp.parsed.unicast_prefix",
	UnicastIPv6Topic:  "gobmp.parsed.unicast_prefix",
	LSNodeTopic:       "gobmp.parsed.ls_node",
	LSLinkTopic:       "gobmp.parsed.ls_link",
	LSPrefixTopic:     "gobmp.parsed.ls_prefix",
	LSSRv6SIDTopic:    "gobmp.parsed.ls_srv6_sid",
	L3VPNIPv4Topic:    "gobmp.parsed.l3vpn",
	L3VPNIPv6Topic:    "gobmp.parsed.l3vpn",
	EVPNTopic:         "gobmp.parsed.evpn",
	SRPolicyIPv4Topic: "gobmp.parsed.sr_policy",
	SRPolicyIPv6Topic: "gobmp.parsed.sr_policy",
	FlowSpecIPv4Topic: "gobmp.parsed.flowspec",
	FlowSpecIPv6Topic: "gobmp.parsed.flowspec",
}

var defaultTopicsConfigSplitAF = kafka.TopicsConfig{
	PeerTopic:         "gobmp.parsed.peer",
	UnicastIPv4Topic:  "gobmp.parsed.unicast_prefix_v4",
	UnicastIPv6Topic:  "gobmp.parsed.unicast_prefix_v6",
	LSNodeTopic:       "gobmp.parsed.ls_node",
	LSLinkTopic:       "gobmp.parsed.ls_link",
	LSPrefixTopic:     "gobmp.parsed.ls_prefix",
	LSSRv6SIDTopic:    "gobmp.parsed.ls_srv6_sid",
	L3VPNIPv4Topic:    "gobmp.parsed.l3vpn_v4",
	L3VPNIPv6Topic:    "gobmp.parsed.l3vpn_v6",
	EVPNTopic:         "gobmp.parsed.evpn",
	SRPolicyIPv4Topic: "gobmp.parsed.sr_policy_v4",
	SRPolicyIPv6Topic: "gobmp.parsed.sr_policy_v6",
	FlowSpecIPv4Topic: "gobmp.parsed.flowspec_v4",
	FlowSpecIPv6Topic: "gobmp.parsed.flowspec_v6",
}

type Config struct {
	KafkaTopics *kafka.TopicsConfig `json:"kafka-topics"`
}

func loadConfig(fp string) (*Config, error) {
	fc, err := ioutil.ReadFile(fp)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %v", err)
	}

	cfg := &Config{}
	err = json.Unmarshal(fc, cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal config file: %v", err)
	}

	return cfg, nil
}

func init() {
	runtime.GOMAXPROCS(1)
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&intercept, "intercept", "false", "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	flag.StringVar(&splitAF, "split-af", "true", "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 56767, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\" or to the standard output when \"dump=console\"")
	flag.StringVar(&file, "msg-file", "/tmp/messages.json", "Full path and file name to store messages when \"dump=file\"")
	flag.StringVar(&configFilePath, "config.file", "", "Path to config file (json)")
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

	var err error
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

	// Starting performance collecting http server
	go func() {
		glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", perfPort), nil))
	}()

	tcfg := defaultTopicsConfig
	if splitAFFlag {
		tcfg = defaultTopicsConfigSplitAF
	}

	if configFilePath != "" {
		cfg, err := loadConfig(configFilePath)
		if err != nil {
			glog.Errorf("Unable to load config: %v", err)
			os.Exit(1)
		}

		if cfg.KafkaTopics != nil {
			tcfg = *cfg.KafkaTopics
		}
	}

	// Initializing publisher
	var publisher pub.Publisher
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
		publisher, err = kafka.NewKafkaPublisher(kafkaSrv, tcfg)
		if err != nil {
			glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	}

	// Initializing bmp server
	bmpSrv, err := gobmpsrv.NewBMPServer(srcPort, dstPort, interceptFlag, publisher)
	if err != nil {
		glog.Errorf("failed to setup new gobmp server with error: %+v", err)
		os.Exit(1)
	}
	// Starting Interceptor server
	bmpSrv.Start()

	stopCh := setupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
	os.Exit(0)
}
