package kafka

// Config holds Kafka client and SASL/TLS options.
type Config struct {
	ServerAddress        string
	TopicRetentionTimeMs string
	// TopicPrefix, when set, is prepended to all Kafka topic names.
	// Example: TopicPrefix="prod" -> "prod.gobmp.parsed.peer"
	TopicPrefix string
	// SkipTopicCreation, when true, does not create topics via the Admin API.
	// Use this with Kafka 4.0+ where the client's CreateTopics API version may be
	// unsupported; pre-create topics manually or with another tool.
	SkipTopicCreation bool

	// SASL (SCRAM) authentication. When SASLUser is non-empty, SASL is enabled.
	// Use with TLS (SASL_SSL) or without (SASL_PLAINTEXT when UseTLS is false).
	// SASLMechanism must be "SCRAM-SHA-512" or "SCRAM-SHA-256".
	SASLUser      string
	SASLPassword  string
	SASLMechanism string // "SCRAM-SHA-512" or "SCRAM-SHA-256"

	// TLS for broker connections. When true, use SASL_SSL (encryption); when false, use SASL_PLAINTEXT if SASL is enabled.
	UseTLS         bool
	TLSSkipVerify  bool   // skip server certificate verification (insecure)
	TLSCAFilePath string // optional path to CA cert (PEM) for server verification
}
