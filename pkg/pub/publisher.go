package pub

// Publisher defines an interface and method to publish message
// msgType is the type of message, defined in pkg/bmp/consts.go
// MsgHash optionally defines the key to use by the backend when storing message
// msg is json marshaled message of msgType
type Publisher interface {
	PublishMessage(msgType int, msgHash []byte, msg []byte) error
}
