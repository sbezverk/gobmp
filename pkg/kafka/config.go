package kafka

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
}
