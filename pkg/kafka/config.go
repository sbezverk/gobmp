package kafka

type Config struct {
	ServerAddress        string
	TopicRetentionTimeMs string
	// TopicPrefix, when set, is prepended to all Kafka topic names.
	// Example: TopicPrefix="prod" -> "prod.gobmp.parsed.peer"
	TopicPrefix string
	// SkipTopicCreation skips the Admin API topic-creation calls on startup.
	// Use with Kafka 4.0+ or clusters where the client lacks CreateTopics
	// permission. Topics must be pre-created before starting gobmp.
	SkipTopicCreation bool
}
