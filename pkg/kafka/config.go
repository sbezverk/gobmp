package kafka

type Config struct {
	ServerAddress string
	// TopicRetentionTimeMs applies only when creating new topics. Existing topics
	// keep their retention policy, and SkipTopicCreation bypasses this setting.
	TopicRetentionTimeMs string
	// TopicPrefix, when set, is prepended to all Kafka topic names.
	// Example: TopicPrefix="prod" -> "prod.gobmp.parsed.peer"
	TopicPrefix string
	// SkipTopicCreation skips the Admin API topic-creation calls on startup.
	// Use with Kafka 4.0+ or clusters where the client lacks CreateTopics
	// permission. Topics must be pre-created before starting gobmp.
	SkipTopicCreation bool
	// TLS enables TLS on connections to the broker. Brokers that terminate TLS
	// on a dedicated listener (commonly :9094) refuse plaintext outright, so
	// this is required to reach them.
	TLS bool
	// CAFile is an optional path to a PEM bundle used to verify the broker's
	// certificate. Empty means the host's system trust store. Only consulted
	// when TLS is set.
	CAFile string
}
