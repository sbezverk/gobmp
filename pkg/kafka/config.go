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

	// SASL (SCRAM) for SASL_SSL clusters.
	// When SASLUser is non-empty, SASL is enabled. SASLMechanism must be "SCRAM-SHA-512" or "SCRAM-SHA-256".
	SASLUser      string
	SASLPassword  string
	SASLMechanism string // "SCRAM-SHA-512" or "SCRAM-SHA-256"

	// TLS for SASL_SSL (encryption). When true, TLS is enabled for broker connections.
	UseTLS         bool
	TLSSkipVerify  bool   // skip server certificate verification (insecure)
	TLSCAFilePath string // optional path to CA cert (PEM) for server verification
}
