package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

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
	splitAF           string
	dump              string
	file              string
	bmpRaw            string
	adminID           string
	configFile        string
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
	defaultPublisherType      = config.PublisherTypeUnknown
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.IntVar(&srcPort, "source-port", defaultSourcePort, "port exposed to outside")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&kafkaTpRetnTimeMs, "kafka-topic-retention-time-ms", defaultKafkaTpRetnTimeMs, "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	flag.StringVar(&kafkaTopicPrefix, "kafka-topic-prefix", "", "Optional prefix prepended to all Kafka topic names (e.g. 'prod' -> 'prod.gobmp.parsed.peer')")
	flag.StringVar(&natsSrv, "nats-server", "", "URL to access NATS server")
	flag.StringVar(&splitAF, "split-af", "", "When set \"true\" ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 0, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Dump resulting messages to file when \"dump=file\", to standard output when \"dump=console\" or to NATS when \"dump=nats\"")
	flag.StringVar(&file, "msg-file", "", "Full path and file name to store messages when \"dump=file\"")
	flag.StringVar(&bmpRaw, "bmp-raw", "", "When set \"true\", BMP messages are published in RAW format without parsing (OpenBMP compatibility mode)")
	flag.StringVar(&adminID, "admin-id", "", "Collector admin ID for RAW messages (defaults to hostname). Used to generate collector hash for OpenBMP compatibility")
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if err == config.ErrNoConfig {
			cfg = &config.Config{}
		} else {
			glog.Errorf("failed to load config with error: %+v", err)
			os.Exit(1)
		}
	}
	applyConfigDefaults(cfg)
	applyConfigOverrides(cfg, flag.CommandLine)

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
		if cfg.KafkaConfig == nil {
			cfg.KafkaConfig = &config.KafkaConfig{}
		}
		kConfig := &kafka.Config{
			ServerAddress:        cfg.KafkaConfig.KafkaSrv,
			TopicRetentionTimeMs: strconv.Itoa(cfg.KafkaConfig.KafkaTpRetnTimeMs),
			TopicPrefix:          cfg.KafkaConfig.KafkaTopicPrefix,
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

	bmpSrv, err := gobmpsrv.NewBMPServer(cfg)
	if err != nil {
		glog.Errorf("failed to setup new gobmp server with error: %+v", err)
		os.Exit(1)
	}
	bmpSrv.Start()

	stopCh := tools.SetupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
	os.Exit(0)
}

func applyConfigDefaults(cfg *config.Config) {
	if cfg.PublisherType == 0 {
		cfg.PublisherType = defaultPublisherType
	}
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
	// This is initialized regardless of the selected publisher so YAML defaults
	// and overrides are always available when Kafka is used.
	if cfg.KafkaConfig == nil {
		cfg.KafkaConfig = &config.KafkaConfig{}
	}
	if cfg.KafkaConfig.KafkaTpRetnTimeMs == 0 {
		if v, err := strconv.Atoi(defaultKafkaTpRetnTimeMs); err == nil {
			cfg.KafkaConfig.KafkaTpRetnTimeMs = v
		}
	}
	// SplitAF is *bool so nil means "not set in YAML". Apply the default (true)
	// only when the pointer is nil; an explicit split_af: false in YAML yields
	// &false and is left untouched.
	if cfg.SplitAF == nil {
		v := defaultSplitAF
		cfg.SplitAF = &v
	}
}

func applyConfigOverrides(cfg *config.Config, fs *flag.FlagSet) {
	// fs.Visit only visits flags explicitly set on the command line,
	// so CLI values safely take precedence over config file and defaults.
	// Sub-structs are lazily initialised so a single CLI flag is enough to
	// create the relevant section without requiring the full block in YAML.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "dump":
			// Map the legacy --dump string to the structured PublisherType so
			// users can select the publisher purely via CLI without a config file.
			switch strings.ToLower(dump) {
			case "file", "console":
				cfg.PublisherType = config.PublisherTypeDump
			case "nats":
				cfg.PublisherType = config.PublisherTypeNATS
			case "kafka":
				cfg.PublisherType = config.PublisherTypeKafka
			}
		case "source-port":
			cfg.BmpListenPort = srcPort
		case "performance-port":
			cfg.PerformancePort = perfPort
			cfg.CollectPerformance = true
		case "split-af":
			if splitAF == "" {
				break
			}
			if v, err := strconv.ParseBool(splitAF); err != nil {
				glog.Errorf("invalid value for --split-af: %q: %v", splitAF, err)
				os.Exit(1)
			} else {
				cfg.SplitAF = &v
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
			if v, err := strconv.Atoi(kafkaTpRetnTimeMs); err != nil {
				glog.Errorf("invalid value for --kafka-topic-retention-time-ms: %q: %v", kafkaTpRetnTimeMs, err)
				os.Exit(1)
			} else {
				cfg.KafkaConfig.KafkaTpRetnTimeMs = v
			}
		case "kafka-topic-prefix":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			cfg.KafkaConfig.KafkaTopicPrefix = kafkaTopicPrefix
		case "bmp-raw":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			if bmpRaw == "" {
				break
			}
			if v, err := strconv.ParseBool(bmpRaw); err != nil {
				glog.Errorf("invalid value for --bmp-raw: %q: %v", bmpRaw, err)
				os.Exit(1)
			} else {
				cfg.KafkaConfig.BmpRaw = v
			}
		case "admin-id":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = &config.KafkaConfig{}
			}
			cfg.KafkaConfig.AdminID = adminID
			if cfg.KafkaConfig.AdminID == "" {
				hostname, err := os.Hostname()
				if err != nil {
					glog.Warningf("failed to get hostname, using 'gobmp-collector' as admin ID: %+v", err)
					cfg.KafkaConfig.AdminID = "gobmp-collector"
				} else {
					cfg.KafkaConfig.AdminID = hostname
				}
			}
		}
	})
	// Double check so if publisher is kafka then AdminID is actually set
	// Infer publisher type from explicit server-URL flags when --dump was not
	// provided. This preserves backward-compatible behaviour: passing
	// --nats-server or --kafka-server alone is enough to select that publisher.
	if cfg.PublisherType == config.PublisherTypeUnknown {
		switch {
		case cfg.NATSConfig != nil && cfg.NATSConfig.NatsSrv != "":
			cfg.PublisherType = config.PublisherTypeNATS
		case cfg.KafkaConfig != nil && cfg.KafkaConfig.KafkaSrv != "":
			cfg.PublisherType = config.PublisherTypeKafka
		}
	}
	// Double check so if publisher is kafka then AdminID is actually set
	if cfg.PublisherType == config.PublisherTypeKafka && cfg.KafkaConfig != nil && cfg.KafkaConfig.AdminID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			cfg.KafkaConfig.AdminID = "gobmp-collector"
		} else {
			cfg.KafkaConfig.AdminID = hostname
		}
	}
}
