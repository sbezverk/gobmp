package bmp

import (
	"encoding/binary"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestPerPeerHeaderRoundTrip(t *testing.T) {
	timestamp := "1599168269.8"
	sec, _ := strconv.Atoi(strings.Split(timestamp, ".")[0])
	msec, _ := strconv.Atoi(strings.Split(timestamp, ".")[1])
	ts := make([]byte, 8)
	binary.BigEndian.PutUint32(ts[0:4], uint32(sec))
	binary.BigEndian.PutUint32(ts[4:8], uint32(msec))
	ipv4peer := make([]byte, 16)
	copy(ipv4peer[12:16], net.ParseIP("192.168.1.1").To4())
	tests := []struct {
		name     string
		original *PerPeerHeader
		fail     bool
	}{
		{
			name: "Valid IPv6 Per Peer Header",
			original: &PerPeerHeader{
				PeerType:          0,
				FlagV:             true,
				FlagA:             true,
				PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
				PeerAS:            5070,
				PeerAddress:       net.ParseIP("2001:1::1").To16(),
				PeerBGPID:         net.ParseIP("1.1.1.1").To4(),
				PeerTimestamp:     ts,
			},
			fail: false,
		},
		{
			name: "Valid IPv4 Per Peer Header",
			original: &PerPeerHeader{
				PeerType:          0,
				FlagV:             false,
				FlagA:             true,
				PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
				PeerAS:            5070,
				PeerAddress:       ipv4peer,
				PeerBGPID:         net.ParseIP("1.1.1.1").To4(),
				PeerTimestamp:     ts,
			},
			fail: false,
		},
		{
			name: "Valid IPv4 Per Peer Header",
			original: &PerPeerHeader{
				PeerType:          3,
				FlagV:             false,
				FlagA:             true,
				PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
				PeerAS:            4200000000,
				PeerAddress:       ipv4peer,
				PeerBGPID:         net.ParseIP("10.10.10.1").To4(),
				PeerTimestamp:     ts,
			},
			fail: false,
		},
		{
			name: "Invalid Per Peer Header ",
			original: &PerPeerHeader{
				PeerType:          4,
				FlagV:             false,
				FlagA:             true,
				PeerDistinguisher: []byte{0, 0, 0, 0, 0, 0, 0, 0},
				PeerAS:            5070,
				PeerAddress:       ipv4peer,
				PeerBGPID:         net.ParseIP("1.1.1.1").To4(),
				PeerTimestamp:     ts,
			},
			fail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.original.Serialize()
			if err != nil {
				t.Fatalf("failed to serialize original common header with error: %+v", err)
			}
			result, err := UnmarshalPerPeerHeader(b)
			if err != nil && !tt.fail {
				t.Fatalf("supposed to succeed but fail with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("supposed to fail but succeeded")
			}
			if !tt.fail {
				if !reflect.DeepEqual(tt.original, result) {
					t.Fatalf("Original: %+v and Resulting: %+v Per Peer Header do not match.", tt.original, result)
				}
			}
		})
	}
}
