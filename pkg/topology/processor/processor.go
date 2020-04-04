package processor

// Messenger defines required methonds of a messaging client
type Messenger interface {
	// SendMessage is used by the messanger client to send message to Processor for processing
	SendMessage(msgType int, msg []byte)
}
