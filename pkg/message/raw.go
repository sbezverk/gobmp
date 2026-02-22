package message

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// headerWriter accumulates binary writes and tracks errors
type headerWriter struct {
	buf bytes.Buffer
	err error
}

// write writes binary data in big-endian format
func (w *headerWriter) write(data interface{}) {
	if w.err != nil {
		return
	}
	w.err = binary.Write(&w.buf, binary.BigEndian, data)
}

// writeBytes writes raw bytes
func (w *headerWriter) writeBytes(b []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.buf.Write(b)
}

// writeString writes a string
func (w *headerWriter) writeString(s string) {
	if w.err != nil {
		return
	}
	_, w.err = w.buf.WriteString(s)
}

// produceRawMessage produces RAW BMP messages in OpenBMP binary format v1.7
// Binary format specification from OpenBMP v2-beta (Constant.h and Encapsulator.cpp)
func (p *producer) produceRawMessage(msg bmp.Message) {
	rm, ok := msg.Payload.(*bmp.RawMessage)
	if !ok {
		glog.Errorf("invalid payload type for RAW message: %T", msg.Payload)
		return
	}

	// Get router IP from peer header, falling back to the TCP speaker IP
	// for message types without a per-peer header (Initiation, Termination).
	var routerIPStr string
	if msg.PeerHeader != nil {
		routerIPStr = msg.PeerHeader.GetPeerAddrString()
	} else if msg.SpeakerIP != "" {
		routerIPStr = msg.SpeakerIP
	} else {
		glog.Errorf("no router IP available, cannot produce RAW message")
		return
	}
	routerIPBytes, err := encodeIPToBytes(routerIPStr)
	if err != nil {
		glog.Errorf("failed to encode router IP: %v", err)
		return
	}

	// Determine if router uses IPv6
	routerIsIPv6 := isIPv6(routerIPStr)

	// Router group - using empty string as gobmp doesn't have router group concept
	routerGroup := ""

	// Calculate collector hash (MD5 of collector admin ID)
	collectorHash := generateMD5Hash([]byte(p.collectorAdminID))

	// Calculate router hash (MD5 of router IP string)
	routerHash := generateMD5Hash([]byte(routerIPStr))

	// Calculate header length
	headerLen := calculateHeaderLength(p.collectorAdminID, routerGroup)

	// Get current timestamp
	timestampSec, timestampUsec := getCurrentTimestamp()

	// Build binary header using error accumulator pattern
	w := &headerWriter{}
	w.buf.Grow(int(headerLen) + len(rm.Msg))

	// Write all fields in big-endian byte order
	w.write(uint32(0x4F424D50))         // Offset 0: Magic Number "OBMP"
	w.write(uint8(1))                   // Offset 4: Version Major
	w.write(uint8(7))                   // Offset 5: Version Minor
	w.write(headerLen)                  // Offset 6: Header Length
	w.write(uint32(len(rm.Msg)))        // Offset 8: BMP Message Length
	w.write(calculateFlags(routerIsIPv6)) // Offset 12: Flags
	w.write(uint8(12))                  // Offset 13: Message Type (BMP_RAW)
	w.write(timestampSec)               // Offset 14: Timestamp Seconds
	w.write(timestampUsec)              // Offset 18: Timestamp Microseconds
	w.writeBytes(collectorHash[:])      // Offset 22: Collector Hash (16 bytes)
	w.write(uint16(len(p.collectorAdminID))) // Offset 38: Collector Admin ID Len
	w.writeString(p.collectorAdminID)   // Offset 40: Collector Admin ID
	w.writeBytes(routerHash[:])         // Offset 40+N: Router Hash (16 bytes)
	w.writeBytes(routerIPBytes[:])      // Offset 56+N: Router IP (16 bytes)
	w.write(uint16(len(routerGroup)))   // Offset 72+N: Router Group Length
	w.writeString(routerGroup)          // Offset 74+N: Router Group
	w.write(uint32(1))                  // Offset 74+N+M: Row Count (always 1)
	w.writeBytes(rm.Msg)                // Append raw BMP message

	// Check for any errors during header construction
	if w.err != nil {
		glog.Errorf("failed to build binary header: %v", w.err)
		return
	}

	// Publish to raw topic
	if err := p.publisher.PublishMessage(bmp.BMPRawMsg, nil, w.buf.Bytes()); err != nil {
		glog.Errorf("failed to publish RAW message: %v", err)
	}
}

// calculateHeaderLength returns total OpenBMP binary header size
func calculateHeaderLength(collectorAdminID, routerGroup string) uint16 {
	return 78 + uint16(len(collectorAdminID)) + uint16(len(routerGroup))
}

// generateMD5Hash creates MD5 hash from input bytes
func generateMD5Hash(input []byte) [16]byte {
	return md5.Sum(input)
}

// encodeIPToBytes converts IP string to 16-byte format
// IPv4: first 4 bytes contain the address, remaining 12 bytes are zero
// IPv6: all 16 bytes contain the address
func encodeIPToBytes(ipStr string) ([16]byte, error) {
	var result [16]byte
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return result, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Convert to 16-byte format
	if ipv4 := ip.To4(); ipv4 != nil {
		// IPv4: first 4 bytes, rest zeros
		copy(result[:4], ipv4)
	} else {
		// IPv6: all 16 bytes
		copy(result[:], ip.To16())
	}
	return result, nil
}

// isIPv6 checks if IP address is IPv6
func isIPv6(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.To4() == nil
}

// calculateFlags returns message flags byte
func calculateFlags(isIPv6 bool) uint8 {
	flags := uint8(0x80) // Always set router message flag (bit 7)
	if isIPv6 {
		flags |= 0x40 // Set IPv6 flag (bit 6)
	}
	return flags
}

// getCurrentTimestamp returns (seconds, microseconds) from current time
func getCurrentTimestamp() (uint32, uint32) {
	now := time.Now()
	return uint32(now.Unix()), uint32(now.UnixNano()/1000 % 1000000)
}
