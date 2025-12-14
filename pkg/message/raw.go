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
	// Note: binary.Write to bytes.Buffer never fails, but we check errors for linter compliance

	// Offset 0: Magic Number (4 bytes) = 0x4F424D50 ("OBMP")
	if err := binary.Write(buf, binary.BigEndian, uint32(0x4F424D50)); err != nil {
		glog.Errorf("failed to write magic number: %v", err)
		return
	}

	// Offset 4: Version Major (1 byte) = 1
	if err := binary.Write(buf, binary.BigEndian, uint8(1)); err != nil {
		glog.Errorf("failed to write version major: %v", err)
		return
	}

	// Offset 5: Version Minor (1 byte) = 7
	if err := binary.Write(buf, binary.BigEndian, uint8(7)); err != nil {
		glog.Errorf("failed to write version minor: %v", err)
		return
	}

	// Offset 6: Header Length (2 bytes)
	if err := binary.Write(buf, binary.BigEndian, headerLen); err != nil {
		glog.Errorf("failed to write header length: %v", err)
		return
	}

	// Offset 8: BMP Message Length (4 bytes)
	if err := binary.Write(buf, binary.BigEndian, uint32(len(rm.Msg))); err != nil {
		glog.Errorf("failed to write BMP message length: %v", err)
		return
	}

	// Offset 12: Flags (1 byte)
	flags := calculateFlags(routerIsIPv6)
	if err := binary.Write(buf, binary.BigEndian, flags); err != nil {
		glog.Errorf("failed to write flags: %v", err)
		return
	}

	// Offset 13: Message Type (1 byte) = 12 (BMP_RAW)
	if err := binary.Write(buf, binary.BigEndian, uint8(12)); err != nil {
		glog.Errorf("failed to write message type: %v", err)
		return
	}

	// Offset 14: Timestamp Seconds (4 bytes)
	if err := binary.Write(buf, binary.BigEndian, timestampSec); err != nil {
		glog.Errorf("failed to write timestamp seconds: %v", err)
		return
	}

	// Offset 18: Timestamp Microseconds (4 bytes)
	if err := binary.Write(buf, binary.BigEndian, timestampUsec); err != nil {
		glog.Errorf("failed to write timestamp microseconds: %v", err)
		return
	}

	// Offset 22: Collector Hash (16 bytes)
	if _, err := buf.Write(collectorHash[:]); err != nil {
		glog.Errorf("failed to write collector hash: %v", err)
		return
	}

	// Offset 38: Collector Admin ID Length (2 bytes)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(p.collectorAdminID))); err != nil {
		glog.Errorf("failed to write collector admin ID length: %v", err)
		return
	}

	// Offset 40: Collector Admin ID (N bytes)
	if _, err := buf.WriteString(p.collectorAdminID); err != nil {
		glog.Errorf("failed to write collector admin ID: %v", err)
		return
	}

	// Offset 40+N: Router Hash (16 bytes)
	if _, err := buf.Write(routerHash[:]); err != nil {
		glog.Errorf("failed to write router hash: %v", err)
		return
	}

	// Offset 56+N: Router IP (16 bytes)
	if _, err := buf.Write(routerIPBytes[:]); err != nil {
		glog.Errorf("failed to write router IP: %v", err)
		return
	}

	// Offset 72+N: Router Group Length (2 bytes)
	if err := binary.Write(buf, binary.BigEndian, uint16(len(routerGroup))); err != nil {
		glog.Errorf("failed to write router group length: %v", err)
		return
	}

	// Offset 74+N: Router Group (M bytes)
	if _, err := buf.WriteString(routerGroup); err != nil {
		glog.Errorf("failed to write router group: %v", err)
		return
	}

	// Offset 74+N+M: Row Count (4 bytes) = 1 (always 1 for BMP_RAW)
	if err := binary.Write(buf, binary.BigEndian, uint32(1)); err != nil {
		glog.Errorf("failed to write row count: %v", err)
		return
	}

	// Append the raw BMP message
	if _, err := buf.Write(rm.Msg); err != nil {
		glog.Errorf("failed to write BMP message: %v", err)
		return
	}

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
