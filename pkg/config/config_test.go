package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "gobmp-config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	return f.Name()
}

func TestLoadConfig_ValidFull(t *testing.T) {
	yml := `
nats_config:
  nats_srv: "nats://localhost:4222"
split_af: true
bmp_listen_port: 5000
performance_port: 56767
active_mode: true
speakers_list:
  - "192.0.2.1:179"
  - "192.0.2.2:179"
`
	path := writeTemp(t, yml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	// PublisherType is yaml:"-" — always zero after LoadConfig; inferred later.
	if cfg.NATSConfig == nil {
		t.Fatal("NATSConfig is nil, want non-nil")
	}
	if cfg.NATSConfig.NatsSrv != "nats://localhost:4222" {
		t.Errorf("NATSConfig.NatsSrv = %q, want nats://localhost:4222", cfg.NATSConfig.NatsSrv)
	}
	if cfg.SplitAF == nil || !*cfg.SplitAF {
		t.Error("SplitAF = nil or false, want *true")
	}
	if cfg.BmpListenPort != 5000 {
		t.Errorf("BmpListenPort = %d, want 5000", cfg.BmpListenPort)
	}
	if cfg.PerformancePort != 56767 {
		t.Errorf("PerformancePort = %d, want 56767", cfg.PerformancePort)
	}
	if !cfg.ActiveMode {
		t.Error("ActiveMode = false, want true")
	}
	if len(cfg.SpeakersList) != 2 {
		t.Fatalf("len(SpeakersList) = %d, want 2", len(cfg.SpeakersList))
	}
	if cfg.SpeakersList[0] != "192.0.2.1:179" {
		t.Errorf("SpeakersList[0] = %q, want 192.0.2.1:179", cfg.SpeakersList[0])
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	path := writeTemp(t, "")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	// PublisherType is yaml:"-" — always zero after LoadConfig; inferred later.
	if cfg.BmpListenPort != 0 {
		t.Errorf("BmpListenPort = %d, want 0", cfg.BmpListenPort)
	}
	if cfg.SplitAF != nil {
		t.Errorf("SplitAF = %v, want nil (unset)", *cfg.SplitAF)
	}
	if cfg.ActiveMode {
		t.Error("ActiveMode = true, want false")
	}
	if len(cfg.SpeakersList) != 0 {
		t.Errorf("SpeakersList = %v, want empty", cfg.SpeakersList)
	}
	if cfg.Publisher != nil {
		t.Error("Publisher should be nil after LoadConfig")
	}
}

func TestLoadConfig_SpeakersListEmpty(t *testing.T) {
	path := writeTemp(t, "active_mode: false\nspeakers_list: []\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if len(cfg.SpeakersList) != 0 {
		t.Errorf("SpeakersList = %v, want empty", cfg.SpeakersList)
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestLoadConfig_FileTooLarge(t *testing.T) {
	content := strings.Repeat("a", maxConfigFileSize+1)
	path := writeTemp(t, content)
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for oversized config file, got nil")
	}
}

func TestLoadConfig_ExactlyMaxSize(t *testing.T) {
	base := "bmp_listen_port: 5000\n"
	padLen := maxConfigFileSize - len(base)
	content := base + "#" + strings.Repeat("x", padLen-1)
	if len(content) != maxConfigFileSize {
		t.Fatalf("test setup: content length %d != %d", len(content), maxConfigFileSize)
	}
	path := writeTemp(t, content)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error at exact max size: %v", err)
	}
	if cfg.BmpListenPort != 5000 {
		t.Errorf("BmpListenPort = %d, want 5000", cfg.BmpListenPort)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "bmp_listen_port: [this is not valid yaml for an int")
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_ComputedFieldNotUnmarshalled(t *testing.T) {
	path := writeTemp(t, "bmp_listen_port: 9000\n")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error: %v", err)
	}
	if cfg.Publisher != nil {
		t.Error("Publisher must remain nil after LoadConfig")
	}
}

func TestLoadConfig_EmptyPath(t *testing.T) {
	_, err := LoadConfig("")
	if err != ErrNoConfig {
		t.Errorf("LoadConfig(\"\") error = %v, want ErrNoConfig", err)
	}
}

func TestLoadConfig_ActiveModeEmptySpeakers(t *testing.T) {
	path := writeTemp(t, "active_mode: true\nspeakers_list: []\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error when active_mode=true and speakers_list is empty, got nil")
	}
}

func TestLoadConfig_ActiveModeInvalidSpeaker(t *testing.T) {
	yml := `
active_mode: true
speakers_list:
  - "not-an-ip:179"
`
	path := writeTemp(t, yml)
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error when active_mode=true and speakers_list contains non-IP address, got nil")
	}
}

func TestLoadConfig_ActiveModeIPv6Speaker(t *testing.T) {
	yml := `
active_mode: true
speakers_list:
  - "[2001:db8::1]:179"
`
	path := writeTemp(t, yml)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() unexpected error for valid IPv6 speaker: %v", err)
	}
	if len(cfg.SpeakersList) != 1 || cfg.SpeakersList[0] != "[2001:db8::1]:179" {
		t.Errorf("SpeakersList = %v, want [\"[2001:db8::1]:179\"]", cfg.SpeakersList)
	}
}

func TestValidateSpeakersList(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "valid single IPv4",
			input:   []string{"192.0.2.1:179"},
			wantErr: false,
		},
		{
			name:    "valid multiple IPv4",
			input:   []string{"192.0.2.1:179", "10.0.0.1:180"},
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			input:   []string{"[2001:db8::1]:179"},
			wantErr: false,
		},
		{
			name:    "valid port boundary low",
			input:   []string{"192.0.2.1:1"},
			wantErr: false,
		},
		{
			name:    "valid port boundary high",
			input:   []string{"192.0.2.1:65535"},
			wantErr: false,
		},
		{
			name:    "empty list is valid",
			input:   []string{},
			wantErr: false,
		},
		{
			name:    "invalid format no port",
			input:   []string{"192.0.2.1"},
			wantErr: true,
		},
		{
			name:    "hostname instead of IP",
			input:   []string{"router.example.com:179"},
			wantErr: true,
		},
		{
			name:    "port zero",
			input:   []string{"192.0.2.1:0"},
			wantErr: true,
		},
		{
			name:    "port too large",
			input:   []string{"192.0.2.1:65536"},
			wantErr: true,
		},
		{
			name:    "non-numeric port",
			input:   []string{"192.0.2.1:bgp"},
			wantErr: true,
		},
		{
			name:    "duplicate address",
			input:   []string{"192.0.2.1:179", "192.0.2.1:179"},
			wantErr: true,
		},
		{
			name:    "second entry invalid keeps first valid",
			input:   []string{"192.0.2.1:179", "bad-entry"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSpeakersList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSpeakersList(%v) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}
