package main

import (
	"errors"
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
	defaultSourcePort        = 5000
	defaultKafkaTpRetnTimeMs = "900000" // 15 minutes in ms
	defaultSplitAF           = true
	defaultMsgFile           = ""
)

func init() {
	flag.StringVar(&configFile, "config", "", "Path to YAML configuration file")
	flag.IntVar(&srcPort, "source-port", defaultSourcePort, "port exposed to outside")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
	flag.StringVar(&kafkaTpRetnTimeMs, "kafka-topic-retention-time-ms", defaultKafkaTpRetnTimeMs, "Kafka topic retention time in ms, default is 900000 ms i.e 15 minutes")
	flag.StringVar(&kafkaTopicPrefix, "kafka-topic-prefix", "", "Optional prefix prepended to all Kafka topic names (e.g. 'prod' -> 'prod.gobmp.parsed.peer')")
	flag.StringVar(&natsSrv, "nats-server", "", "URL to access NATS server")
	flag.StringVar(&splitAF, "split-af", "true", "When set \"true\" ipv4 and ipv6 will be published in separate topics. if set \"false\" the same topic will be used for both address families.")
	flag.IntVar(&perfPort, "performance-port", 0, "port used for performance debugging")
	flag.StringVar(&dump, "dump", "", "Selects the dump publisher: 'console' prints JSON messages to stdout, 'file' writes them to the path set by --msg-file (falls back to console if --msg-file is omitted)")
	flag.StringVar(&file, "msg-file", "", "Full path and file name to store messages when \"--dump=file\"")
	flag.StringVar(&bmpRaw, "bmp-raw", "false", "When set \"true\", BMP messages are published in RAW format without parsing (OpenBMP compatibility mode)")
	flag.StringVar(&adminID, "admin-id", "", "Collector admin ID for RAW messages (defaults to hostname). Used to generate collector hash for OpenBMP compatibility")
}

// fatal logs msg at error level, flushes glog's buffer, and exits with code 1.
// os.Exit skips deferred calls, so glog's own deferred flush would never run;
// calling glog.Flush() explicitly here ensures the error message is always
// visible on stderr before the process terminates.
func fatal(format string, args ...interface{}) {
	glog.Errorf(format, args...)
	glog.Flush()
	os.Exit(1)
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		if errors.Is(err, config.ErrNoConfig) {
			cfg = &config.Config{}
		} else {
			fatal("failed to load config with error: %+v", err)
		}
	}
	applyConfigDefaults(cfg)
	if err := applyConfigOverrides(cfg, flag.CommandLine); err != nil {
		fatal("configuration error: %v", err)
	}

	// Starting performance collecting http server if required
	if cfg.PerformancePort > 0 {
		go func() {
			glog.Info(http.ListenAndServe(fmt.Sprintf(":%d", cfg.PerformancePort), nil))
		}()
	}
	// Initializing publisher
	switch cfg.PublisherType {
	case config.PublisherTypeDump:
		// applyConfigOverrides only sets PublisherTypeDump when --dump is "console"
		// or "file", so dumpMode is guaranteed to be one of those two values here.
		switch strings.ToLower(dump) {
		case "console":
			cfg.Publisher = dumper.NewDumper()
			glog.Infof("console publisher has been successfully initialized (dump=console).")
		case "file":
			if cfg.DumpConfig != nil && cfg.DumpConfig.File != "" {
				cfg.Publisher, err = filer.NewFiler(cfg.DumpConfig.File)
				if err != nil {
					fatal("failed to initialize file publisher with error: %+v", err)
				} else {
					glog.Infof("file publisher has been successfully initialized (dump=file).")
				}
			} else {
				glog.Warningf("dump=file requested but no dump file configured; falling back to console publisher.")
				cfg.Publisher = dumper.NewDumper()
				glog.Infof("console publisher has been successfully initialized (fallback from dump=file).")
			}
		}
	case config.PublisherTypeNATS:
		if cfg.NATSConfig != nil && cfg.NATSConfig.NatsSrv != "" {
			cfg.Publisher, err = nats.NewPublisher(cfg.NATSConfig.NatsSrv)
			if err != nil {
				fatal("failed to initialize NATS publisher with error: %+v", err)
			} else {
				glog.Infof("NATS publisher has been successfully initialized.")
			}
		} else {
			fatal("NATS server URL is required for NATS publisher")
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
			fatal("failed to initialize Kafka publisher with error: %+v", err)
		}
		glog.Infof("Kafka publisher has been successfully initialized.")
	default:
		fatal("no publisher configured: specify --kafka-server, --nats-server, or --dump")
	}

	bmpSrv, err := gobmpsrv.NewBMPServer(cfg)
	if err != nil {
		fatal("failed to setup new gobmp server with error: %+v", err)
	}
	bmpSrv.Start()

	stopCh := tools.SetupSignalHandler()
	<-stopCh

	bmpSrv.Stop()
}

// defaultKafkaConfig returns a KafkaConfig pre-populated with the retention-
// time default. Used when any Kafka CLI flag triggers lazy initialisation so
// that --kafka-server alone (without --kafka-topic-retention-time-ms) still
// gets the correct default.
func defaultKafkaConfig() *config.KafkaConfig {
	v, _ := strconv.Atoi(defaultKafkaTpRetnTimeMs)
	return &config.KafkaConfig{KafkaTpRetnTimeMs: v}
}

func applyConfigDefaults(cfg *config.Config) {
	// PublisherType is always reset to Unknown here; the actual type is
	// inferred from populated sub-configs in applyConfigOverrides.
	cfg.PublisherType = config.PublisherTypeUnknown
	if cfg.BmpListenPort == 0 {
		cfg.BmpListenPort = defaultSourcePort
	}
	// PerformancePort > 0 enables pprof. No default port is applied here;
	// the user must set an explicit port to opt in.
	// DumpConfig: ensure sub-struct exists and apply file default.
	if cfg.DumpConfig == nil {
		cfg.DumpConfig = &config.DumpConfig{}
	}
	if cfg.DumpConfig.File == "" {
		cfg.DumpConfig.File = defaultMsgFile
	}
	// KafkaConfig is initialised only when it was already present (e.g. loaded
	// from a YAML kafka_config block). For NATS-only or dump-only users the
	// struct stays nil so the publisher inference nil check remains meaningful.
	// When Kafka CLI flags are used, applyConfigOverrides lazily creates the
	// struct and applies the retention-time default at that point.
	if cfg.KafkaConfig != nil && cfg.KafkaConfig.KafkaTpRetnTimeMs == 0 {
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

func applyConfigOverrides(cfg *config.Config, fs *flag.FlagSet) error {
	// fs.Visit only visits flags explicitly set on the command line,
	// so CLI values safely take precedence over config file and defaults.
	// Sub-structs are lazily initialised so a single CLI flag is enough to
	// create the relevant section without requiring the full block in YAML.
	// visitErr captures the first error from inside the closure (fs.Visit
	// does not support early termination, so we skip further cases once set).
	var visitErr error
	var bmpRawSet, adminIDSet bool
	fs.Visit(func(f *flag.Flag) {
		if visitErr != nil {
			return
		}
		switch f.Name {
		case "dump":
			// The dump publisher writes to console (stdout) or to a file determined
			// by --msg-file. Kafka and NATS are separate publishers selected via
			// --kafka-server and --nats-server respectively.
			switch strings.ToLower(dump) {
			case "file", "console":
				cfg.PublisherType = config.PublisherTypeDump
			default:
				visitErr = fmt.Errorf("invalid value for --dump: %q: must be 'console' or 'file'", dump)
			}
		case "source-port":
			cfg.BmpListenPort = srcPort
		case "performance-port":
			// Negative values are invalid. Zero explicitly disables pprof (port=0 → no listener).
			if perfPort < 0 {
				visitErr = fmt.Errorf("invalid value for --performance-port: %d: must be >= 0", perfPort)
				return
			}
			cfg.PerformancePort = perfPort
		case "split-af":
			if splitAF == "" {
				visitErr = fmt.Errorf("invalid empty value for --split-af: must be 'true' or 'false'")
				return
			}
			if v, err := strconv.ParseBool(splitAF); err != nil {
				visitErr = fmt.Errorf("invalid value for --split-af: %q: %w", splitAF, err)
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
				cfg.KafkaConfig = defaultKafkaConfig()
			}
			cfg.KafkaConfig.KafkaSrv = kafkaSrv
		case "kafka-topic-retention-time-ms":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = defaultKafkaConfig()
			}
			if v, err := strconv.Atoi(kafkaTpRetnTimeMs); err != nil {
				visitErr = fmt.Errorf("invalid value for --kafka-topic-retention-time-ms: %q: %w", kafkaTpRetnTimeMs, err)
			} else {
				cfg.KafkaConfig.KafkaTpRetnTimeMs = v
			}
		case "kafka-topic-prefix":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = defaultKafkaConfig()
			}
			cfg.KafkaConfig.KafkaTopicPrefix = kafkaTopicPrefix
		case "bmp-raw":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = defaultKafkaConfig()
			}
			if bmpRaw == "" {
				visitErr = errors.New("invalid empty value for --bmp-raw")
				return
			}
			if v, err := strconv.ParseBool(bmpRaw); err != nil {
				visitErr = fmt.Errorf("invalid value for --bmp-raw: %q: %w", bmpRaw, err)
			} else {
				cfg.KafkaConfig.BmpRaw = v
				bmpRawSet = true
			}
		case "admin-id":
			if cfg.KafkaConfig == nil {
				cfg.KafkaConfig = defaultKafkaConfig()
			}
			cfg.KafkaConfig.AdminID = adminID
			adminIDSet = true
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
	if visitErr != nil {
		return visitErr
	}
	// Infer publisher type from explicit server-URL flags when --dump was not
	// provided. This preserves backward-compatible behaviour: passing
	// --nats-server or --kafka-server alone is enough to select that publisher.
	// If both are given without an explicit --dump, return an error rather than
	// silently picking one.
	if cfg.PublisherType == config.PublisherTypeUnknown {
		hasNATS := cfg.NATSConfig != nil && cfg.NATSConfig.NatsSrv != ""
		hasKafka := cfg.KafkaConfig != nil && cfg.KafkaConfig.KafkaSrv != ""
		switch {
		case hasNATS && hasKafka:
			return fmt.Errorf("ambiguous publisher configuration: both NATS and Kafka are configured (via CLI flags and/or config file); configure only one publisher (NATS or Kafka)")
		case hasNATS:
			cfg.PublisherType = config.PublisherTypeNATS
		case hasKafka:
			cfg.PublisherType = config.PublisherTypeKafka
		}
	}
	// Ensure AdminID is set whenever Kafka is the selected publisher.
	if cfg.PublisherType == config.PublisherTypeKafka && cfg.KafkaConfig != nil && cfg.KafkaConfig.AdminID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			glog.Warningf("failed to get hostname, using 'gobmp-collector' as admin ID: %+v", err)
			cfg.KafkaConfig.AdminID = "gobmp-collector"
		} else {
			cfg.KafkaConfig.AdminID = hostname
		}
	}
	// Warn when Kafka-specific flags were provided but Kafka is not the selected
	// publisher. The flags are accepted (not an error) to avoid breaking
	// scripted invocations, but the operator should know they have no effect.
	if cfg.PublisherType != config.PublisherTypeKafka {
		if bmpRawSet {
			glog.Warningf("--bmp-raw is set but has no effect: it only applies to the Kafka publisher (current publisher: %v)", cfg.PublisherType)
		}
		if adminIDSet {
			glog.Warningf("--admin-id is set but has no effect: it only applies to the Kafka publisher (current publisher: %v)", cfg.PublisherType)
		}
	}
	return nil
}
