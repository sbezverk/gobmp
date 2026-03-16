package bmp

// Message defines a message used to transfer BMP messages for further processing
// for BMP messages which do not carry PerPeerHeader, it will be set to nil.
type Message struct {
	PeerHeader *PerPeerHeader
	Payload    interface{}
	// SpeakerIP is the BMP speaker's IP address from the TCP connection.
	// Used as fallback router IP for message types without a per-peer header
	// (Initiation, Termination) per RFC 7854 Section 4.3/4.5.
	SpeakerIP string
}
