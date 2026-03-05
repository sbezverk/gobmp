package bmp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

// PeerUpMessage defines BMPPeerUpMessage per rfc7854
type PeerUpMessage struct {
	LocalAddress     []byte
	LocalPort        uint16
	RemotePort       uint16
	SentOpen         *bgp.OpenMessage
	ReceivedOpen     *bgp.OpenMessage
	Information      []InformationalTLV
	isRemotePeerIPv6 bool
}

// GetLocalAddressString returns the local address as a string, properly formatted as IPv4 or IPv6 based on the isRemotePeerIPv6 flag.
func (pum *PeerUpMessage) GetLocalAddressString() string {
	if pum.isRemotePeerIPv6 {
		return net.IP(pum.LocalAddress).To16().String()
	}
	return net.IP(pum.LocalAddress[12:]).To4().String()
}

// GetVRFTableName returns the VRF table name from the Peer Up message's Informational TLVs, if present.
func (pum *PeerUpMessage) GetVRFTableName() (string, bool) {
	for _, tlv := range pum.Information {
		if tlv.InformationType != 3 {
			continue
		}
		return string(tlv.Information), true
	}
	return "", false
}

// GetAdminLabel returns the administrative label from the Peer Up message's Informational TLVs, if present.
func (pum *PeerUpMessage) GetAdminLabel() (string, bool) {
	for _, tlv := range pum.Information {
		if tlv.InformationType != 4 {
			continue
		}
		return string(tlv.Information), true
	}
	return "", false
}

// UnmarshalPeerUpMessage processes Peer Up message and returns BMPPeerUpMessage object
func UnmarshalPeerUpMessage(b []byte, isIPv6 bool) (*PeerUpMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Peer Up Message Raw: %s", tools.MessageHex(b))
	}
	var err error
	pu := &PeerUpMessage{
		LocalAddress:     make([]byte, 16),
		SentOpen:         &bgp.OpenMessage{},
		ReceivedOpen:     &bgp.OpenMessage{},
		Information:      make([]InformationalTLV, 0),
		isRemotePeerIPv6: isIPv6,
	}
	p := 0
	if p+16 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Local Address, need 16 bytes, have %d", len(b)-p)
	}
	copy(pu.LocalAddress, b[:16])
	p += 16
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Local Port, need 2 bytes, have %d", len(b)-p)
	}
	pu.LocalPort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Remote Port, need 2 bytes, have %d", len(b)-p)
	}
	pu.RemotePort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+16 > len(b) {
		return nil, fmt.Errorf("not enough bytes for BGP 1st marker, need 16 bytes, have %d", len(b)-p)
	}
	// Skip first marker 16 bytes
	p += 16
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Sent Open message length, need 2 bytes, have %d", len(b)-p)
	}
	l1 := binary.BigEndian.Uint16(b[p : p+2])
	if l1 < 16 {
		return nil, fmt.Errorf("invalid BGP Open message length %d, less than minimum 16 bytes", l1)
	}
	if p+int(l1)-16 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Sent Open message, need %d bytes, have %d", int(l1)-16, len(b)-p)
	}
	pu.SentOpen, err = bgp.UnmarshalBGPOpenMessage(b[p : p+int(l1)-16])
	if err != nil {
		return nil, err
	}
	// Moving pointer to the next marker
	p += int(l1) - 16
	// Skip second marker
	if p+16 > len(b) {
		return nil, fmt.Errorf("not enough bytes for BGP 2nd marker, need 16 bytes, have %d", len(b)-p)
	}
	p += 16
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Received Open message length, need 2 bytes, have %d", len(b)-p)
	}
	l2 := binary.BigEndian.Uint16(b[p : p+2])
	if l2 < 16 {
		return nil, fmt.Errorf("invalid BGP Open message length %d, less than minimum 16 bytes", l2)
	}
	if p+int(l2)-16 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Received Open message, need %d bytes, have %d", int(l2)-16, len(b)-p)
	}
	pu.ReceivedOpen, err = bgp.UnmarshalBGPOpenMessage(b[p : p+int(l2)-16])
	if err != nil {
		return nil, err
	}
	p += int(l2) - 16
	// Last part is optional Informational TLVs
	if len(b) > int(p) {
		// Since pointer p does not point to the end of buffer,
		// then processing Informational TLVs
		tlvs, err := UnmarshalTLV(b[p:])
		if err != nil {
			return nil, err
		}
		pu.Information = tlvs
	}
	return pu, nil
}
