package kafka

import "testing"

func TestValidator(t *testing.T) {
	const validRetention = "900000"
	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: validRetention},
			wantErr: false,
		},
		{
			name:    "valid config with skip topic creation",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: validRetention, SkipTopicCreation: true},
			wantErr: false,
		},
		{
			name:    "missing port",
			cfg:     &Config{ServerAddress: "127.0.0.1", TopicRetentionTimeMs: validRetention},
			wantErr: true,
		},
		{
			name:    "empty host",
			cfg:     &Config{ServerAddress: ":9092", TopicRetentionTimeMs: validRetention},
			wantErr: true,
		},
		{
			name:    "invalid retention",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "not-a-number"},
			wantErr: true,
		},
		{
			name:    "retention below -1",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "-2"},
			wantErr: true,
		},
		{
			name:    "retention -1 is allowed",
			cfg:     &Config{ServerAddress: "127.0.0.1:9092", TopicRetentionTimeMs: "-1"},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("validator() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
