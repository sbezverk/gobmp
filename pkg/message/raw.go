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

// produceRawMessage produces RAW BMP messages in OpenBMP binary format v1.7
// Binary format specification from OpenBMP v2-beta (Constant.h and Encapsulator.cpp)
func (p *producer) produceRawMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("peer header is nil, cannot produce RAW message")
		return
	}

	rm, ok := msg.Payload.(*bmp.RawMessage)
	if !ok {
		glog.Errorf("invalid payload type for RAW message: %T", msg.Payload)
		return
	}

	// Get router IP from peer header
	routerIPStr := msg.PeerHeader.GetPeerAddrString()
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

	// Create buffer for entire message (header + BMP message)
	totalSize := int(headerLen) + len(rm.Msg)
	buf := new(bytes.Buffer)
	buf.Grow(totalSize)

	// Write all fields in big-endian byte order

	// Offset 0: Magic Number (4 bytes) = 0x4F424D50 ("OBMP")
	binary.Write(buf, binary.BigEndian, uint32(0x4F424D50))

	// Offset 4: Version Major (1 byte) = 1
	binary.Write(buf, binary.BigEndian, uint8(1))

	// Offset 5: Version Minor (1 byte) = 7
	binary.Write(buf, binary.BigEndian, uint8(7))

	// Offset 6: Header Length (2 bytes)
	binary.Write(buf, binary.BigEndian, headerLen)

	// Offset 8: BMP Message Length (4 bytes)
	binary.Write(buf, binary.BigEndian, uint32(len(rm.Msg)))

	// Offset 12: Flags (1 byte)
	flags := calculateFlags(routerIsIPv6)
	binary.Write(buf, binary.BigEndian, flags)

	// Offset 13: Message Type (1 byte) = 12 (BMP_RAW)
	binary.Write(buf, binary.BigEndian, uint8(12))

	// Offset 14: Timestamp Seconds (4 bytes)
	binary.Write(buf, binary.BigEndian, timestampSec)

	// Offset 18: Timestamp Microseconds (4 bytes)
	binary.Write(buf, binary.BigEndian, timestampUsec)

	// Offset 22: Collector Hash (16 bytes)
	buf.Write(collectorHash[:])

	// Offset 38: Collector Admin ID Length (2 bytes)
	binary.Write(buf, binary.BigEndian, uint16(len(p.collectorAdminID)))

	// Offset 40: Collector Admin ID (N bytes)
	buf.WriteString(p.collectorAdminID)

	// Offset 40+N: Router Hash (16 bytes)
	buf.Write(routerHash[:])

	// Offset 56+N: Router IP (16 bytes)
	buf.Write(routerIPBytes[:])

	// Offset 72+N: Router Group Length (2 bytes)
	binary.Write(buf, binary.BigEndian, uint16(len(routerGroup)))

	// Offset 74+N: Router Group (M bytes)
	buf.WriteString(routerGroup)

	// Offset 74+N+M: Row Count (4 bytes) = 1 (always 1 for BMP_RAW)
	binary.Write(buf, binary.BigEndian, uint32(1))

	// Append the raw BMP message
	buf.Write(rm.Msg)

	// Publish to raw topic
	if err := p.publisher.PublishMessage(bmp.BMPRawMsg, nil, buf.Bytes()); err != nil {
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
