package kafka

import "strings"

// WithTopicPrefix prepends prefix to the provided topic name.
// If prefix is empty or whitespace, topic is returned unchanged.
// Example: prefix="prod" and topic="gobmp.parsed.peer" -> "prod.gobmp.parsed.peer".
func WithTopicPrefix(prefix, topic string) string {
	p := strings.TrimSpace(prefix)
	if p == "" {
		return topic
	}
	p = strings.Trim(p, ".")
	if p == "" {
		return topic
	}
	return p + "." + topic
}

