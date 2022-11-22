package bgp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// BGPMinNotificationMessageLength defines a minimum length of BGP Open Message
	BGPMinNotificationMessageLength = 21
)

// OpenMessage defines BGP Open Message structure
type NotificationMessage struct {
	Length       int16
	Type         byte
	ErrorCode    byte
	ErrorSubCode byte
	Data         []byte
}

// UnmarshalBGPNotificationMessage validate information passed in byte slice and returns BGPNotificationMessage object
func UnmarshalBGPNotificationMessage(b []byte) (*NotificationMessage, error) {
	if glog.V(6) {
		glog.Infof("BGPNotificationMessage Raw: %s", tools.MessageHex(b))
	}
	if len(b) < BGPMinNotificationMessageLength {
		return nil, fmt.Errorf("BGP Notification Message length %d is invalid", len(b))
	}
	p := 0
	m := NotificationMessage{}
	p += 16
	m.Length = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	if b[p] != 3 {
		return nil, fmt.Errorf("invalid message type %d for BGP Notification Message", b[p])
	}
	m.Type = b[p]
	p++
	m.ErrorCode = b[p]
	p++
	m.ErrorSubCode = b[p]
	p++
	if p < len(b) {
		l := len(b) - p
		m.Data = make([]byte, l)
		copy(m.Data, b[p:p+l])
	}
	return &m, nil
}

// Message Header Error Subcodes
// 0x01 Connection Not Synchronized.
// 0x02	Bad Message Length.
// 0x03	Bad Message Type.
var messageHeaderErrorSubErrors = map[byte]string{
	0x1: "Connection Not Synchronized",
	0x2: "Bad Message Length",
	0x3: "Bad Message Type",
}

// Open Message Error Subcodes
// 0x01 - Unsupported Version Number.
// 0x02 - Bad Peer AS.
// 0x03 - Bad BGP Identifier.
// 0x04 - Unsupported Optional Parameter.
// 0x05 - [Deprecated - see Appendix A].
// 0x06 - Unacceptable Hold Time.
var openMessageErrorSubErrors = map[byte]string{
	0x1: "Unsupported Version Number",
	0x2: "Bad Peer AS",
	0x3: "Bad BGP Identifier",
	0x4: "Unsupported Optional Parameter",
	0x5: "Deprecated",
	0x6: "Unacceptable Hold Time",
}

// Update Message Error Subcodes
// 0x01 - Malformed Attribute List.
// 0x02 - Unrecognized Well-known Attribute.
// 0x03 - Missing Well-known Attribute.
// 0x04 - Attribute Flags Error.
// 0x05 - Attribute Length Error.
// 0x06 - Invalid ORIGIN Attribute.
// 0x07 - [Deprecated - see Appendix A].
// 0x08 - Invalid NEXT_HOP Attribute.
// 0x09 - Optional Attribute Error.
// 0x0A - Invalid Network Field.
// 0x0B - Malformed AS_PATH.
var updateMessageErrorSubErrors = map[byte]string{
	0x1:  "Malformed Attribute List",
	0x2:  "Unrecognized Well-known Attribute",
	0x3:  "Missing Well-known Attribute",
	0x4:  "Attribute Flags Error",
	0x5:  "Attribute Length Error",
	0x6:  "Invalid ORIGIN Attribute",
	0x7:  "[Deprecated - see Appendix A]",
	0x8:  "Invalid NEXT_HOP Attribute",
	0x9:  "Optional Attribute Error",
	0x10: "Invalid Network Field",
	0x11: "Malformed AS_PATH",
}

// Hold Time Expired. No sub error code is defined.
var holdTimeExpiredSubErrors = map[uint8]string{
	0x00: "",
}

// Fsm Error. No sub error code is defined.
var fsmErrorSubErrors = map[uint8]string{
	0x00: "",
}

// Cease Error. No sub error code is defined.
var ceaseErrorSubErrors = map[uint8]string{
	0x00: "",
}

func getErrorSubError(m map[uint8]string, subType uint8) string {
	s := " Unknown Sub Error Code"
	if s, ok := m[subType]; ok {
		return s
	}
	return s
}

// BGP Message Header Error
func messageHeaderError(subType uint8, value byte) string {
	return "Message Header Error, Sub Error:" + getErrorSubError(messageHeaderErrorSubErrors, subType)
}

// BGP Open Message Error
func openMessageError(subType uint8, value byte) string {
	return "Open Message Error, Sub Error:" + getErrorSubError(openMessageErrorSubErrors, subType)
}

// BGP Update Message Error
func updateMessageError(subType uint8, value byte) string {
	return "Update Message Error, Sub Error:" + getErrorSubError(updateMessageErrorSubErrors, subType)
}

// Hold Time Expired Message Error
func holdTimeExpired(subType uint8, value byte) string {
	return "Hold Time Expired" + getErrorSubError(holdTimeExpiredSubErrors, subType)
}

// FSM Error
func fmsError(subType uint8, value byte) string {
	return "FSM Error" + getErrorSubError(fsmErrorSubErrors, subType)
}

// Cease Error
func ceaseError(subType uint8, value byte) string {
	return "Cease Error" + getErrorSubError(ceaseErrorSubErrors, subType)
}

// errCode defines a map with errorCode as a key, it return a function to process a type specific sub type error.
var errCode = map[uint8]func(uint8, byte) string{
	0x1: messageHeaderError,
	0x2: openMessageError,
	0x3: updateMessageError,
	0x4: holdTimeExpired,
	0x5: fmsError,
	0x6: ceaseError,
}

func (msg *NotificationMessage) String() string {
	var s string
	ErrorSubCode := msg.ErrorSubCode

	f := errCode[msg.ErrorCode]
	if f == nil {
		s = "unknown="
		s += fmt.Sprintf("Error: %d SubError: %d", msg.ErrorCode, ErrorSubCode)
		return s
	}
	return f(ErrorSubCode, msg.ErrorCode)
}
