package bmp

// Message defines a message used to transfer BMP messages for further processing
// for BMP messages which do not carry PerPeerHeader, it will be set to nil.
type Message struct {
	PeerHeader *PerPeerHeader
	Payload    interface{}
}
