package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/sbezverk/gobmp/pkg/pub"
	"gopkg.in/yaml.v3"
)

const (
	maxConfigFileSize = 1024 * 1024 // 1 MB
)

var ErrNoConfig = errors.New("no config file provided")

type PublisherType int

const (
	PublisherTypeUnknown PublisherType = iota // 0 — zero value; a fresh Config{} is safe by default
	PublisherTypeDump                         // 1
	PublisherTypeNATS                         // 2
	PublisherTypeKafka                        // 3
)

func (pt PublisherType) String() string {
	switch pt {
	case PublisherTypeDump:
		return "Dump"
	case PublisherTypeNATS:
		return "NATS"
	case PublisherTypeKafka:
		return "Kafka"
	default:
		return "Unknown"
	}
}

type DumpConfig struct {
	File string `yaml:"file"`
}

type NATSConfig struct {
	NatsSrv string `yaml:"nats_srv"`
}

type KafkaConfig struct {
	KafkaSrv          string `yaml:"kafka_srv"`
	KafkaTpRetnTimeMs int    `yaml:"kafka_tp_retn_time_ms"`
	KafkaTopicPrefix  string `yaml:"kafka_topic_prefix"`
	BmpRaw            bool   `yaml:"bmp_raw"`
	AdminID           string `yaml:"admin_id"`
}

type Config struct {
	// Computed fields — not persisted to YAML.
	Publisher     pub.Publisher `yaml:"-"`
	PublisherType PublisherType `yaml:"-"` // always inferred, never stored in YAML
	// Fields from config file
	KafkaConfig     *KafkaConfig `yaml:"kafka_config"`
	NATSConfig      *NATSConfig  `yaml:"nats_config"`
	DumpConfig      *DumpConfig  `yaml:"dump_config"`
	SplitAF         *bool        `yaml:"split_af"`
	BmpListenPort   int          `yaml:"bmp_listen_port"`
	PerformancePort int          `yaml:"performance_port"` // > 0 enables pprof collection
	ActiveMode      bool         `yaml:"active_mode"`
	SpeakersList    []string     `yaml:"speakers_list"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{}
	if path == "" {
		return nil, ErrNoConfig
	}
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fd.Close()
	}()

	fi, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxConfigFileSize {
		return nil, fmt.Errorf("config file size exceeds the maximum allowed size of %d bytes", maxConfigFileSize)
	}
	size := int(fi.Size())
	if size == 0 {
		// Empty config file: treat as empty YAML document and load defaults.
		if err := yaml.Unmarshal([]byte{}, cfg); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(fd, b); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if cfg.ActiveMode && len(cfg.SpeakersList) == 0 {
		return nil, errors.New("active_mode is true but speakers_list is empty")
	}
	if cfg.ActiveMode {
		if err := ValidateSpeakersList(cfg.SpeakersList); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

func ValidateSpeakersList(speakers []string) error {
	uniqueAddrs := make(map[string]bool)
	for _, addr := range speakers {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("invalid speaker address %q: must be in the form <ip-literal>:<port>: %v", addr, err)
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid speaker address %q: host %q is not a valid IP literal (speakers_list only accepts IP literals, not hostnames or scoped addresses)", addr, host)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid speaker address %q: invalid port %q (must be between 1 and 65535)", addr, port)
		}
		if _, exists := uniqueAddrs[addr]; exists {
			return fmt.Errorf("duplicate speaker address: %q", addr)
		}
		uniqueAddrs[addr] = true
	}

	return nil
}
