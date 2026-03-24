package config

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
	"gopkg.in/yaml.v3"
)

const (
	MAX_CONFIG_FILE_SIZE = 1024 // 1 KB
)

var ErrNoConfig = errors.New("no config file provided")

type PublisherType int

const (
	PublisherTypeDump PublisherType = iota
	PublisherTypeNATS
	PublisherTypeKafka
)

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
	// Computed fields
	Publisher pub.Publisher `yaml:"-"`
	// Fields from config file
	PublisherType      PublisherType `yaml:"publisher_type"`
	KafkaConfig        *KafkaConfig  `yaml:"kafka_config"`
	NATSConfig         *NATSConfig   `yaml:"nats_config"`
	DumpConfig         *DumpConfig   `yaml:"dump_config"`
	BmpRaw             bool          `yaml:"bmp_raw"`
	AdminID            string        `yaml:"admin_id"`
	SplitAF            bool          `yaml:"split_af"`
	BmpListenPort      int           `yaml:"bmp_listen_port"`
	CollectPerformance bool          `yaml:"collect_performance"`
	PerformancePort    int           `yaml:"performance_port"`
	ActiveMode         bool          `yaml:"active_mode"`
	SpeakersList       []string      `yaml:"speakers_list"`
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
	defer fd.Close()

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MAX_CONFIG_FILE_SIZE {
		return nil, fmt.Errorf("config file size exceeds the maximum allowed size of %d bytes", MAX_CONFIG_FILE_SIZE)
	}
	b := make([]byte, fi.Size())
	n, err := io.ReadAtLeast(fd, b, int(fi.Size()))
	if err != nil {
		return nil, err
	}
	if n != int(fi.Size()) {
		return nil, fmt.Errorf("expected to read %d bytes but read %d bytes", fi.Size(), n)
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
