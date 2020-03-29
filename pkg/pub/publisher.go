package pub

// Publisher defines an interface and method to publish message
type Publisher interface {
	PublishMessage(int, []byte, []byte) error
}
