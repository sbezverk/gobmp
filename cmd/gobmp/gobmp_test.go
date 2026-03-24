package main

import (
	"flag"
	"os"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/config"
)

func TestMain(m *testing.M) {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	rc := m.Run()
	os.Exit(rc)

}
func TestCommonHeader(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *bmp.CommonHeader
		fail   bool
	}{
		{
			name:  "valid",
			input: []byte{3, 0, 0, 0, 32, 4},
			expect: &bmp.CommonHeader{
				Version:       3,
				MessageLength: 32,
				MessageType:   4,
			},
			fail: false,
		},
		{
			name:   "invalid version",
			input:  []byte{33, 0, 0, 0, 32, 4},
			expect: nil,
			fail:   true,
		},
		{
			// RFC 7854 §4.1: unknown message types MUST be ignored, not rejected.
			// UnmarshalCommonHeader logs a warning and returns the parsed header.
			name:  "unknown type 10 — accepted per RFC 7854",
			input: []byte{3, 0, 0, 0, 32, 10},
			expect: &bmp.CommonHeader{
				Version:       3,
				MessageLength: 32,
				MessageType:   10,
			},
			fail: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := bmp.UnmarshalCommonHeader(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}

func TestInitiationMessage(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *bmp.InitiationMessage
		fail   bool
	}{
		{
			name:  "valid 2 TLVs",
			input: []byte{0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: &bmp.InitiationMessage{
				TLV: []bmp.InformationalTLV{
					{
						InformationType:   1,
						InformationLength: 10,
						Information:       []byte{32, 55, 46, 50, 46, 49, 46, 50, 51, 73},
					},
					{
						InformationType:   2,
						InformationLength: 8,
						Information:       []byte{120, 114, 118, 57, 107, 45, 114, 49},
					},
				},
			},
			fail: false,
		},
		{
			// RFC 7854 extensibility: unknown TLV types must be silently accepted.
			name:  "unknown TLV type 3 — accepted per RFC 7854 extensibility",
			input: []byte{0, 3, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: &bmp.InitiationMessage{
				TLV: []bmp.InformationalTLV{
					{
						InformationType:   3,
						InformationLength: 10,
						Information:       []byte{32, 55, 46, 50, 46, 49, 46, 50, 51, 73},
					},
					{
						InformationType:   2,
						InformationLength: 8,
						Information:       []byte{120, 114, 118, 57, 107, 45, 114, 49},
					},
				},
			},
			fail: false,
		},
		{
			name:   "invalid 2 TLVs wrong length 100",
			input:  []byte{0, 1, 0, 100, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49},
			expect: nil,
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := bmp.UnmarshalInitiationMessage(tt.input)
			if err != nil {
				if !tt.fail {
					t.Fatal("expected to succeed but failed")
				}
			}
			if err == nil {
				if tt.fail {
					t.Fatal("expected to fail but succeeded")
				}
			}
			if !reflect.DeepEqual(message, tt.expect) {
				t.Error("unmarshaled and expected messages do not much")
			}
		})
	}
}

// ---- applyConfigDefaults ----------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func TestApplyConfigDefaults_ZeroCfg(t *testing.T) {
	cfg := &config.Config{}
	applyConfigDefaults(cfg)

	if cfg.PublisherType != defaultPublisherType {
		t.Errorf("PublisherType = %d, want %d", cfg.PublisherType, defaultPublisherType)
	}
	if cfg.BmpListenPort != defaultSourcePort {
		t.Errorf("BmpListenPort = %d, want %d", cfg.BmpListenPort, defaultSourcePort)
	}
	if cfg.PerformancePort != defaultPerfPort {
		t.Errorf("PerformancePort = %d, want %d", cfg.PerformancePort, defaultPerfPort)
	}
	if cfg.DumpConfig == nil {
		t.Fatal("DumpConfig is nil, want non-nil")
	}
	if cfg.DumpConfig.File != defaultMsgFile {
		t.Errorf("DumpConfig.File = %q, want %q", cfg.DumpConfig.File, defaultMsgFile)
	}
	if cfg.KafkaConfig == nil {
		t.Fatal("KafkaConfig is nil, want non-nil")
	}
	wantRetention := 900000
	if cfg.KafkaConfig.KafkaTpRetnTimeMs != wantRetention {
		t.Errorf("KafkaConfig.KafkaTpRetnTimeMs = %d, want %d", cfg.KafkaConfig.KafkaTpRetnTimeMs, wantRetention)
	}
	// SplitAF nil → default true must be applied.
	if cfg.SplitAF == nil || !*cfg.SplitAF {
		t.Error("SplitAF = nil or false, want *true (default)")
	}
}

func TestApplyConfigDefaults_SplitAF_ExplicitFalse_Preserved(t *testing.T) {
	cfg := &config.Config{SplitAF: boolPtr(false)}
	applyConfigDefaults(cfg)

	// An explicit split_af: false from YAML (≠ nil) must not be overwritten.
	if cfg.SplitAF == nil || *cfg.SplitAF {
		t.Error("explicit *false SplitAF was overwritten by defaults")
	}
}

func TestApplyConfigDefaults_PresetValues_NotOverwritten(t *testing.T) {
	cfg := &config.Config{
		PublisherType:   config.PublisherTypeNATS,
		BmpListenPort:   9999,
		PerformancePort: 1234,
		SplitAF:         boolPtr(false), // explicit false from YAML
		DumpConfig:      &config.DumpConfig{File: "custom.json"},
		KafkaConfig:     &config.KafkaConfig{KafkaTpRetnTimeMs: 42},
	}
	applyConfigDefaults(cfg)

	if cfg.PublisherType != config.PublisherTypeNATS {
		t.Errorf("PublisherType overwritten, got %d", cfg.PublisherType)
	}
	if cfg.BmpListenPort != 9999 {
		t.Errorf("BmpListenPort overwritten, got %d", cfg.BmpListenPort)
	}
	if cfg.PerformancePort != 1234 {
		t.Errorf("PerformancePort overwritten, got %d", cfg.PerformancePort)
	}
	if cfg.DumpConfig.File != "custom.json" {
		t.Errorf("DumpConfig.File overwritten, got %q", cfg.DumpConfig.File)
	}
	if cfg.KafkaConfig.KafkaTpRetnTimeMs != 42 {
		t.Errorf("KafkaConfig.KafkaTpRetnTimeMs overwritten, got %d", cfg.KafkaConfig.KafkaTpRetnTimeMs)
	}
	if cfg.SplitAF == nil || *cfg.SplitAF {
		t.Error("SplitAF overwritten to true, expected *false to be preserved")
	}
}

func TestApplyConfigDefaults_SplitAF_AlreadyTrue_NotChanged(t *testing.T) {
	cfg := &config.Config{SplitAF: boolPtr(true)}
	applyConfigDefaults(cfg)
	if cfg.SplitAF == nil || !*cfg.SplitAF {
		t.Error("SplitAF was *true and should remain *true")
	}
}

// ---- applyConfigOverrides ---------------------------------------------------

// resetOverrideGlobals zeros every global var that applyConfigOverrides reads.
// This prevents flags marked as visited in an earlier test from applying
// stale values to the cfg under test — flag.Visit cannot be "un-visited",
// but zeroing the underlying global makes each visited case a no-op for fields
// not under test.
func resetOverrideGlobals() {
	srcPort = 0
	perfPort = 0
	splitAF = ""
	natsSrv = ""
	file = ""
	dump = ""
	kafkaSrv = ""
	kafkaTpRetnTimeMs = ""
	kafkaTopicPrefix = ""
	bmpRaw = ""
	adminID = ""
}

func TestApplyConfigOverrides_Dump_File(t *testing.T) {
	resetOverrideGlobals()
	dump = "file"
	flag.Set("dump", "file")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeDump {
		t.Errorf("PublisherType = %d, want PublisherTypeDump (%d)", cfg.PublisherType, config.PublisherTypeDump)
	}
}

func TestApplyConfigOverrides_Dump_Console(t *testing.T) {
	resetOverrideGlobals()
	dump = "console"
	flag.Set("dump", "console")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeDump {
		t.Errorf("PublisherType = %d, want PublisherTypeDump (%d)", cfg.PublisherType, config.PublisherTypeDump)
	}
}

func TestApplyConfigOverrides_Dump_NATS(t *testing.T) {
	resetOverrideGlobals()
	dump = "nats"
	flag.Set("dump", "nats")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeNATS {
		t.Errorf("PublisherType = %d, want PublisherTypeNATS (%d)", cfg.PublisherType, config.PublisherTypeNATS)
	}
}

func TestApplyConfigOverrides_Dump_Kafka(t *testing.T) {
	resetOverrideGlobals()
	dump = "kafka"
	flag.Set("dump", "kafka")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeKafka {
		t.Errorf("PublisherType = %d, want PublisherTypeKafka (%d)", cfg.PublisherType, config.PublisherTypeKafka)
	}
}

func TestApplyConfigOverrides_NatsServer_InfersPublisherType(t *testing.T) {
	resetOverrideGlobals()
	natsSrv = "nats://127.0.0.1:4222"
	flag.Set("nats-server", "nats://127.0.0.1:4222")

	cfg := &config.Config{PublisherType: config.PublisherTypeUnknown}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeNATS {
		t.Errorf("PublisherType = %d, want PublisherTypeNATS (%d)", cfg.PublisherType, config.PublisherTypeNATS)
	}
}

func TestApplyConfigOverrides_KafkaServer_InfersPublisherType(t *testing.T) {
	resetOverrideGlobals()
	kafkaSrv = "kafka:9092"
	flag.Set("kafka-server", "kafka:9092")

	cfg := &config.Config{PublisherType: config.PublisherTypeUnknown}
	applyConfigOverrides(cfg)

	if cfg.PublisherType != config.PublisherTypeKafka {
		t.Errorf("PublisherType = %d, want PublisherTypeKafka (%d)", cfg.PublisherType, config.PublisherTypeKafka)
	}
}

func TestApplyConfigOverrides_SourcePort(t *testing.T) {
	resetOverrideGlobals()
	srcPort = 9000
	flag.Set("source-port", "9000")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.BmpListenPort != 9000 {
		t.Errorf("BmpListenPort = %d, want 9000", cfg.BmpListenPort)
	}
}

func TestApplyConfigOverrides_PerformancePort(t *testing.T) {
	resetOverrideGlobals()
	perfPort = 8080
	flag.Set("performance-port", "8080")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.PerformancePort != 8080 {
		t.Errorf("PerformancePort = %d, want 8080", cfg.PerformancePort)
	}
}

func TestApplyConfigOverrides_SplitAF(t *testing.T) {
	resetOverrideGlobals()
	splitAF = "true"
	flag.Set("split-af", "true")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.SplitAF == nil || !*cfg.SplitAF {
		t.Error("SplitAF = nil or false, want *true")
	}
}

func TestApplyConfigOverrides_NatsServer_LazyInit(t *testing.T) {
	resetOverrideGlobals()
	natsSrv = "nats://127.0.0.1:4222"
	flag.Set("nats-server", "nats://127.0.0.1:4222")

	cfg := &config.Config{} // NATSConfig starts nil
	applyConfigOverrides(cfg)

	if cfg.NATSConfig == nil {
		t.Fatal("NATSConfig is nil, want non-nil (lazy init)")
	}
	if cfg.NATSConfig.NatsSrv != "nats://127.0.0.1:4222" {
		t.Errorf("NATSConfig.NatsSrv = %q, want nats://127.0.0.1:4222", cfg.NATSConfig.NatsSrv)
	}
}

func TestApplyConfigOverrides_MsgFile_LazyInit(t *testing.T) {
	resetOverrideGlobals()
	file = "/tmp/override.json"
	flag.Set("msg-file", "/tmp/override.json")

	cfg := &config.Config{} // DumpConfig starts nil
	applyConfigOverrides(cfg)

	if cfg.DumpConfig == nil {
		t.Fatal("DumpConfig is nil, want non-nil (lazy init)")
	}
	if cfg.DumpConfig.File != "/tmp/override.json" {
		t.Errorf("DumpConfig.File = %q, want /tmp/override.json", cfg.DumpConfig.File)
	}
}

func TestApplyConfigOverrides_KafkaServer_LazyInit(t *testing.T) {
	resetOverrideGlobals()
	kafkaSrv = "kafka:9092"
	flag.Set("kafka-server", "kafka:9092")

	cfg := &config.Config{} // KafkaConfig starts nil
	applyConfigOverrides(cfg)

	if cfg.KafkaConfig == nil {
		t.Fatal("KafkaConfig is nil, want non-nil (lazy init)")
	}
	if cfg.KafkaConfig.KafkaSrv != "kafka:9092" {
		t.Errorf("KafkaConfig.KafkaSrv = %q, want kafka:9092", cfg.KafkaConfig.KafkaSrv)
	}
}

func TestApplyConfigOverrides_KafkaRetentionTime(t *testing.T) {
	resetOverrideGlobals()
	kafkaTpRetnTimeMs = "1800000"
	flag.Set("kafka-topic-retention-time-ms", "1800000")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.KafkaConfig == nil {
		t.Fatal("KafkaConfig is nil, want non-nil")
	}
	if cfg.KafkaConfig.KafkaTpRetnTimeMs != 1800000 {
		t.Errorf("KafkaConfig.KafkaTpRetnTimeMs = %d, want 1800000", cfg.KafkaConfig.KafkaTpRetnTimeMs)
	}
}

func TestApplyConfigOverrides_KafkaTopicPrefix(t *testing.T) {
	resetOverrideGlobals()
	kafkaTopicPrefix = "prod"
	flag.Set("kafka-topic-prefix", "prod")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.KafkaConfig == nil {
		t.Fatal("KafkaConfig is nil, want non-nil")
	}
	if cfg.KafkaConfig.KafkaTopicPrefix != "prod" {
		t.Errorf("KafkaConfig.KafkaTopicPrefix = %q, want prod", cfg.KafkaConfig.KafkaTopicPrefix)
	}
}

func TestApplyConfigOverrides_BmpRaw(t *testing.T) {
	resetOverrideGlobals()
	bmpRaw = "true"
	flag.Set("bmp-raw", "true")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if !cfg.BmpRaw {
		t.Error("BmpRaw = false, want true")
	}
}

func TestApplyConfigOverrides_AdminID_Explicit(t *testing.T) {
	resetOverrideGlobals()
	adminID = "my-collector"
	flag.Set("admin-id", "my-collector")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	if cfg.AdminID != "my-collector" {
		t.Errorf("AdminID = %q, want my-collector", cfg.AdminID)
	}
}

func TestApplyConfigOverrides_AdminID_Empty_FallsBackToHostname(t *testing.T) {
	resetOverrideGlobals()
	// adminID is already "" from reset; flag.Set marks "admin-id" as visited
	// so the case executes and hits the hostname fallback branch.
	flag.Set("admin-id", "")

	cfg := &config.Config{}
	applyConfigOverrides(cfg)

	// The fallback sets AdminID to the OS hostname (or "gobmp-collector" on error).
	// We cannot predict the exact value, so assert it is non-empty.
	if cfg.AdminID == "" {
		t.Error("AdminID is empty after hostname fallback, want non-empty")
	}
	wantHostname, _ := os.Hostname()
	if wantHostname != "" && cfg.AdminID != wantHostname {
		t.Errorf("AdminID = %q, want hostname %q", cfg.AdminID, wantHostname)
	}
}
