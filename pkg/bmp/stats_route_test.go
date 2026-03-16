package bmp

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestUnmarshalBMPStatsReportMessage(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		wantCount uint32
		wantTLVs  int
	}{
		{
			name:    "buffer too short (0 bytes)",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "buffer too short (3 bytes)",
			input:   []byte{0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:      "count=0 no TLVs",
			input:     []byte{0x00, 0x00, 0x00, 0x00},
			wantErr:   false,
			wantCount: 0,
			wantTLVs:  0,
		},
		{
			name: "count=1 with one valid TLV",
			input: func() []byte {
				b := make([]byte, 4+4+4)
				binary.BigEndian.PutUint32(b[0:], 1) // count=1
				binary.BigEndian.PutUint16(b[4:], 0) // TLV type=0
				binary.BigEndian.PutUint16(b[6:], 4) // TLV length=4
				binary.BigEndian.PutUint32(b[8:], 42)
				return b
			}(),
			wantErr:   false,
			wantCount: 1,
			wantTLVs:  1,
		},
		{
			name: "count=2 with two TLVs",
			input: func() []byte {
				b := make([]byte, 4+4+4+4+8)
				binary.BigEndian.PutUint32(b[0:], 2)
				binary.BigEndian.PutUint16(b[4:], 1)
				binary.BigEndian.PutUint16(b[6:], 4)
				binary.BigEndian.PutUint32(b[8:], 100)
				binary.BigEndian.PutUint16(b[12:], 2)
				binary.BigEndian.PutUint16(b[14:], 8)
				binary.BigEndian.PutUint64(b[16:], 99999)
				return b
			}(),
			wantErr:   false,
			wantCount: 2,
			wantTLVs:  2,
		},
		{
			name: "count larger than buffer allows",
			input: func() []byte {
				// count claims 1000 TLVs but buffer is only 4 bytes after header
				b := make([]byte, 4+4)
				binary.BigEndian.PutUint32(b[0:], 1000)
				// one tiny TLV to keep TLV parsing valid but count check fires first
				binary.BigEndian.PutUint16(b[4:], 0)
				binary.BigEndian.PutUint16(b[6:], 0)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "count=1 but TLV value overflows buffer",
			input: func() []byte {
				b := make([]byte, 4+4+2) // only 2 value bytes, but length claims 100
				binary.BigEndian.PutUint32(b[0:], 1)
				binary.BigEndian.PutUint16(b[4:], 0)
				binary.BigEndian.PutUint16(b[6:], 100) // length=100 but only 2 value bytes
				return b
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalBMPStatsReportMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBMPStatsReportMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.StatsCount != tt.wantCount {
				t.Errorf("StatsCount = %d, want %d", got.StatsCount, tt.wantCount)
			}
			if len(got.StatsTLV) != tt.wantTLVs {
				t.Errorf("len(StatsTLV) = %d, want %d", len(got.StatsTLV), tt.wantTLVs)
			}
		})
	}
}

func TestUnmarshalBMPRouteMonitorMessage(t *testing.T) {
	// Build a minimal valid Route Monitor body:
	// 16-byte marker + 2-byte length + 1-byte type (non-2) = 19 bytes minimum
	makeBody := func(msgType byte, length uint16) []byte {
		b := make([]byte, 16+2+1)
		for i := 0; i < 16; i++ {
			b[i] = 0xFF // BGP marker
		}
		binary.BigEndian.PutUint16(b[16:], length)
		b[18] = msgType
		return b
	}

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "too short (0 bytes)",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "too short (18 bytes — missing type byte)",
			input:   make([]byte, 18),
			wantErr: true,
		},
		{
			name:    "non-update type (type=1 OPEN) — error, unexpected type",
			input:   makeBody(1, 19),
			wantErr: true,
		},
		{
			name:    "non-update type (type=3 NOTIFICATION) — error, unexpected type",
			input:   makeBody(3, 19),
			wantErr: true,
		},
		{
			// type=2 UPDATE with nothing after the type byte — BGP layer rejects it
			// because there are not enough bytes for the Withdrawn Routes Length field.
			name:    "update type with empty payload errors from BGP layer",
			input:   makeBody(2, 19),
			wantErr: true,
		},
		{
			name:    "bgpLen understated (claims 19 but buffer is 25)",
			input:   append(makeBody(2, 19), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
			wantErr: true,
		},
		{
			name:    "bgpLen too small (claims 10)",
			input:   makeBody(2, 10),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBMPRouteMonitorMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBMPRouteMonitorMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRouteMonitor_ErrNotAnUpdate(t *testing.T) {
	makeBody := func(msgType byte, length uint16) []byte {
		b := make([]byte, 16+2+1)
		for i := 0; i < 16; i++ {
			b[i] = 0xFF
		}
		binary.BigEndian.PutUint16(b[16:], length)
		b[18] = msgType
		return b
	}
	_, err := UnmarshalBMPRouteMonitorMessage(makeBody(4, 19))
	if err == nil {
		t.Fatal("expected error for KEEPALIVE type")
	}
	if !errors.Is(err, ErrNotAnUpdate) {
		t.Errorf("error %v does not wrap ErrNotAnUpdate", err)
	}
}

func TestGetPeerAddrString_ShortAddress(t *testing.T) {
	p := &PerPeerHeader{
		PeerAddress: []byte{10, 0, 0, 1},
	}
	got := p.GetPeerAddrString()
	if got != "" {
		t.Errorf("got %q, want empty string for short address", got)
	}
}

func TestGetPeerAddrString_ValidIPv4(t *testing.T) {
	addr := make([]byte, 16)
	addr[12], addr[13], addr[14], addr[15] = 10, 0, 0, 1
	p := &PerPeerHeader{
		PeerType:    PeerType0,
		PeerAddress: addr,
	}
	got := p.GetPeerAddrString()
	if got != "10.0.0.1" {
		t.Errorf("got %q, want '10.0.0.1'", got)
	}
}
