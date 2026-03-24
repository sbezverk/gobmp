package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"net/http"
	_ "net/http/pprof"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/config"
	"github.com/sbezverk/gobmp/pkg/dumper"
	"github.com/sbezverk/gobmp/pkg/filer"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/kafka"
	"github.com/sbezverk/gobmp/pkg/nats"
	"github.com/sbezverk/tools"
)

var (
	// dstPort           int
	srcPort           int
	perfPort          int
	kafkaSrv          string
	kafkaTpRetnTimeMs string // Kafka topic retention time in ms
	kafkaTopicPrefix  string
	natsSrv           string
	// intercept         string
	splitAF    string
	dump       string
	file       string
	bmpRaw     string
	adminID    string
	configFile string
)

const (
	defaultSourcePort         = 5000
	defaultPerformanceCollect = false
	defaultPerfPort           = 56767
	defaultKafkaTpRetnTimeMs  = "900000" // 15 minutes in ms
	defaultSplitAF            = true
	defaultBmpRaw             = false
	defaultMsgFile            = ""
	defaultAdminID            = ""
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.IntVar(&srcPort, "source-port", defaultSourcePort, "port exposed to outside")
	//	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&kafkaTpRetnTimeMs, "kafka-topic-retention-time-ms", defaultKafkaTpRetnTimeMs, "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	flag.StringVar(&kafkaTopicPrefix, "kafka-topic-prefix", "", "Optional prefix prepended to all Kafka topic names (e.g. 'prod' -> 'prod.gobmp.parsed.peer')")
	flag.StringVar(&natsSrv, "nats-server", "", "URL to access NATS server")
	//	flag.StringVar(&intercept, "intercept", "false", "When intercept set \"true\", all incomming BMP messges will be copied to TCP port specified by destination-port, otherwise received BMP messages will be published to Kafka.")
	flag.StringVar(&splitAF, "split-af", "", "When set \"true\" (default) ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 0, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\", to standard output when \"dump=console\" or to NATS when \"dump=nats\"")
	flag.StringVar(&file, "msg-file", "", "Full path anf file name to store messages when \"dump=file\"")
	flag.StringVar(&bmpRaw, "bmp-raw", "", "When set \"true\", BMP messages are published in RAW format without parsing (OpenBMP compatibility mode)")
	flag.StringVar(&adminID, "admin-id", "", "Collector admin ID for RAW messages (defaults to hostname). Used to generate collector hash for OpenBMP compatibility")
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	configLoaded := true
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		configLoaded = false
		if err == config.ErrNoConfig {
			cfg = &config.Config{}
		} else {
			glog.Errorf("failed to load config with error: %+v", err)
			os.Exit(1)
		}
	}
	applyConfigDefaults(cfg, configLoaded)
	applyConfigOverrides(cfg)

	// Starting performance collecting http server if required
	if cfg.CollectPerformance {
		go func() {
			glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", cfg.PerformancePort), nil))
		}()
	}
	// Initializing publisher
	switch cfg.PublisherType {
	case config.PublisherTypeDump:
		if cfg.DumpConfig != nil && cfg.DumpConfig.File != "" {
			cfg.Publisher, err = filer.NewFiler(cfg.DumpConfig.File)
			if err != nil {
				glog.Errorf("failed to initialize file publisher with error: %+v", err)
				os.Exit(1)
			} else {
				glog.V(5).Infof("file publisher has been successfully initialized.")
			}
		} else {
			cfg.Publisher = dumper.NewDumper()
			glog.V(5).Infof("console publisher has been successfully initialized.")
		}
	case config.PublisherTypeNATS:
		if cfg.NATSConfig != nil && cfg.NATSConfig.NatsSrv != "" {
			cfg.Publisher, err = nats.NewPublisher(cfg.NATSConfig.NatsSrv)
			if err != nil {
				glog.Errorf("failed to initialize NATS publisher with error: %+v", err)
				os.Exit(1)
			} else {
				glog.V(5).Infof("NATS publisher has been successfully initialized.")
			}
		} else {
			glog.Error("NATS server URL is required for NATS publisher")
			os.Exit(1)
		}
	case config.PublisherTypeKafka:
		kConfig := &kafka.Config{
			ServerAddress:        kafkaSrv,
			TopicRetentionTimeMs: kafkaTpRetnTimeMs,
			TopicPrefix:          kafkaTopicPrefix,
		}
		cfg.Publisher, err = kafka.NewKafkaPublisher(kConfig)
		if err != nil {
			glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
			os.Exit(1)
		}
		glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	default:
		glog.Errorf("invalid publisher type: %d", cfg.PublisherType)
		os.Exit(1)
	}

	// var publisher pub.Publisher
	// switch strings.ToLower(dump) {
	// case "file":
	// 	publisher, err = filer.NewFiler(file)
	// 	if err != nil {
	// 		glog.Errorf("failed to initialize file publisher with error: %+v", err)
	// 		os.Exit(1)
	// 	}
	// 	glog.V(5).Infof("file publisher has been successfully initialized.")
	// case "console":
	// 	publisher = dumper.NewDumper()
	// 	glog.V(5).Infof("console publisher has been successfully initialized.")
	// case "nats":
	// 	publisher, err = nats.NewPublisher(natsSrv)
	// 	if err != nil {
	// 		glog.Errorf("failed to initialize NATS publisher with error: %+v", err)
	// 		os.Exit(1)
	// 	}
	// 	glog.V(5).Infof("NATS publisher has been successfully initialized.")
	// default:
	// 	kConfig := &kafka.Config{
	// 		ServerAddress:        kafkaSrv,
	// 		TopicRetentionTimeMs: kafkaTpRetnTimeMs,
	// 		TopicPrefix:          kafkaTopicPrefix,
	// 	}
	// 	publisher, err = kafka.NewKafkaPublisher(kConfig)
	// 	if err != nil {
	// 		glog.Errorf("failed to initialize Kafka publisher with error: %+v", err)
	// 		os.Exit(1)
	// 	}
	// 	glog.V(5).Infof("Kafka publisher has been successfully initialized.")
	// }

	// Initializing bmp server
	// interceptFlag, err := strconv.ParseBool(intercept)
	// if err != nil {
	// 	glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
	// 	os.Exit(1)
	// }
	// splitAFFlag, err := strconv.ParseBool(splitAF)
	// if err != nil {
	// 	glog.Errorf("failed to parse to bool the value of the intercept flag with error: %+v", err)
	// 	os.Exit(1)
	// }
	// bmpRawFlag, err := strconv.ParseBool(bmpRaw)
	// if err != nil {
	// 	glog.Errorf("failed to parse to bool the value of the bmp-raw flag with error: %+v", err)
	// 	os.Exit(1)
	// }

	// Set default admin ID to hostname if not provided
	// collectorAdminID := adminID
	// if collectorAdminID == "" {
	// 	hostname, err := os.Hostname()
	// 	if err != nil {
	// 		glog.Warningf("failed to get hostname, using 'gobmp-collector' as admin ID: %+v", err)
	// 		collectorAdminID = "gobmp-collector"
	// 	} else {
	// 		collectorAdminID = hostname
	// 	}
	// }

	bmpSrv, err := gobmpsrv.NewBMPServer(cfg)
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

func applyConfigDefaults(cfg *config.Config, configLoaded bool) {
	if cfg.BmpListenPort == 0 {
		cfg.BmpListenPort = defaultSourcePort
	}
	if cfg.PerformancePort == 0 {
		cfg.PerformancePort = defaultPerfPort
	}
	// DumpConfig: ensure sub-struct exists and apply file default.
	if cfg.DumpConfig == nil {
		cfg.DumpConfig = &config.DumpConfig{}
	}
	if cfg.DumpConfig.File == "" {
		cfg.DumpConfig.File = defaultMsgFile
	}
	// KafkaConfig: ensure sub-struct exists and apply retention time default.
	// Kafka is the default publisher so this is always initialised.
	if cfg.KafkaConfig == nil {
		cfg.KafkaConfig = &config.KafkaConfig{}
	}
	if cfg.KafkaConfig.KafkaTpRetnTimeMs == 0 {
		if v, err := strconv.Atoi(defaultKafkaTpRetnTimeMs); err == nil {
			cfg.KafkaConfig.KafkaTpRetnTimeMs = v
		}
	}
	// SplitAF defaults to true. Since bool zero-value is false, we can only safely
	// apply the default when no config file was loaded — otherwise we cannot distinguish
	// "not set in YAML" from "explicitly set to false".
	if !configLoaded && !cfg.SplitAF {
		cfg.SplitAF = defaultSplitAF
	}
}

func applyConfigOverrides(cfg *config.Config) {
	// flag.Visit only visits flags explicitly set on the command line,
	// so CLI values safely take precedence over config file and defaults.
	// Sub-structs are lazily initialised so a single CLI flag is enough to
	// create the relevant section without requiring the full block in YAML.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "source-port":
			cfg.BmpListenPort = srcPort
		case "performance-port":
			cfg.PerformancePort = perfPort
		case "split-af":
			if v, err := strconv.ParseBool(splitAF); err == nil {
				cfg.SplitAF = v
			}
		case "nats-server":
			if cfg.NATSConfig == nil {
				cfg.NATSConfig = &config.NATSConfig{}
			}
			cfg.NATSConfig.NatsSrv = natsSrv
		case "msg-file":
			if cfg.DumpConfig == nil {
				cfg.DumpConfig = &config.DumpConfig{}
			}
			cfg.DumpConfig.File = file
		case "kafka-server":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			cfg.KafkaConfig.KafkaSrv = kafkaSrv
		case "kafka-topic-retention-time-ms":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			if v, err := strconv.Atoi(kafkaTpRetnTimeMs); err == nil {
				cfg.KafkaConfig.KafkaTpRetnTimeMs = v
			}
		case "kafka-topic-prefix":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			cfg.KafkaConfig.KafkaTopicPrefix = kafkaTopicPrefix
		case "bmp-raw":
			if v, err := strconv.ParseBool(bmpRaw); err == nil {
				cfg.BmpRaw = v
			}
		case "admin-id":
			cfg.AdminID = adminID
			if cfg.AdminID == "" {
				hostname, err := os.Hostname()
				if err != nil {
					glog.Warningf("failed to get hostname, using 'gobmp-collector' as admin ID: %+v", err)
					cfg.AdminID = "gobmp-collector"
				} else {
					cfg.AdminID = hostname
				}
			}
		}
	})
}
