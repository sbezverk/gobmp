package bmp

import (
	"encoding/binary"
	"errors"
	"testing"
)

func routeMirrorTestBGPMessage(msgType byte, body []byte) []byte {
	message := make([]byte, 19+len(body))
	for i := 0; i < 16; i++ {
		message[i] = 0xff
	}
	binary.BigEndian.PutUint16(message[16:18], uint16(len(message)))
	message[18] = msgType
	copy(message[19:], body)
	return message
}

func routeMirrorTestTLV(tlvType uint16, value []byte) []byte {
	tlv := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(tlv[:2], tlvType)
	binary.BigEndian.PutUint16(tlv[2:4], uint16(len(value)))
	copy(tlv[4:], value)
	return tlv
}

func TestUnmarshalBMPRouteMirrorMessageUpdate(t *testing.T) {
	// An empty UPDATE is the IPv4-unicast End-of-RIB marker. The BGP Message
	// TLV contains the complete BGP PDU, not just the UPDATE body.
	pdu := routeMirrorTestBGPMessage(2, []byte{0, 0, 0, 0})
	wire := routeMirrorTestTLV(uint16(RouteMirrorBGPMsgTLV), pdu)

	got, err := UnmarshalBMPRouteMirrorMessage(wire)
	if err != nil {
		t.Fatalf("UnmarshalBMPRouteMirrorMessage() error = %v", err)
	}
	if got == nil {
		t.Fatal("UnmarshalBMPRouteMirrorMessage() returned nil message")
	}
	update, err := got.GetBGPUpdate()
	if err != nil {
		t.Fatalf("GetBGPUpdate() error = %v", err)
	}
	if update == nil {
		t.Fatal("GetBGPUpdate() returned nil update")
	}
	if len(update.PathAttributes) != 0 || len(update.NLRI) != 0 || update.WithdrawnRoutesLength != 0 {
		t.Fatalf("decoded update = %+v, want empty IPv4 EOR UPDATE", update)
	}
	if len(got.TLVs) != 1 || string(got.TLVs[0].Value) != string(pdu) {
		t.Fatal("decoder did not retain the full BGP PDU in the BGP Message TLV")
	}
}

func TestUnmarshalBMPRouteMirrorMessageTLVValidation(t *testing.T) {
	pdu := routeMirrorTestBGPMessage(2, []byte{0, 0, 0, 0})
	info := routeMirrorTestTLV(uint16(RouteMirrorInfoTLV), []byte{0, 1})
	unknown := routeMirrorTestTLV(100, []byte{0xaa})
	bUpdate := routeMirrorTestTLV(uint16(RouteMirrorBGPMsgTLV), pdu)

	tests := []struct {
		name    string
		wire    []byte
		wantErr bool
	}{
		{name: "multiple non-BGP TLVs are allowed", wire: append(append([]byte{}, info...), unknown...)},
		{name: "information TLV before final BGP TLV", wire: append(append([]byte{}, info...), bUpdate...)},
		{name: "BGP TLV before later TLV is rejected", wire: append(append([]byte{}, bUpdate...), info...), wantErr: true},
		{name: "truncated TLV header", wire: []byte{0, 1, 0}, wantErr: true},
		{name: "short trailing TLV header", wire: append(append([]byte{}, unknown...), 0, 1), wantErr: true},
		{name: "truncated TLV value", wire: []byte{0, 1, 0, 2, 0}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalBMPRouteMirrorMessage(tt.wire)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBMPRouteMirrorMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnmarshalBMPRouteMirrorMessageNonUpdate(t *testing.T) {
	pdu := routeMirrorTestBGPMessage(4, nil) // KEEPALIVE
	wire := routeMirrorTestTLV(uint16(RouteMirrorBGPMsgTLV), pdu)
	_, err := UnmarshalBMPRouteMirrorMessage(wire)
	if !errors.Is(err, ErrNotAnUpdate) {
		t.Fatalf("error = %v, want ErrNotAnUpdate", err)
	}
}

func TestRouteMirrorGetBGPUpdateErrors(t *testing.T) {
	tests := []struct {
		name string
		rm   *RouteMirror
	}{
		{name: "no BGP or information TLV", rm: &RouteMirror{}},
		{name: "information length is too short", rm: &RouteMirror{TLVs: []TLV{{Type: RouteMirrorInfoTLV, Length: 1, Value: []byte{0}}}}},
		{name: "information value is shorter than its declared code", rm: &RouteMirror{TLVs: []TLV{{Type: RouteMirrorInfoTLV, Length: 2, Value: []byte{0}}}}},
		{name: "errored PDU code", rm: &RouteMirror{TLVs: []TLV{{Type: RouteMirrorInfoTLV, Length: 2, Value: []byte{0, 0}}}}},
		{name: "messages lost code", rm: &RouteMirror{TLVs: []TLV{{Type: RouteMirrorInfoTLV, Length: 2, Value: []byte{0, 1}}}}},
		{name: "unknown information code", rm: &RouteMirror{TLVs: []TLV{{Type: RouteMirrorInfoTLV, Length: 2, Value: []byte{0x12, 0x34}}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if update, err := tt.rm.GetBGPUpdate(); err == nil || update != nil {
				t.Fatalf("GetBGPUpdate() = (%v, %v), want error and nil update", update, err)
			}
		})
	}
}

func TestUnmarshalBMPRouteMirrorMessageInvalidBGPUpdate(t *testing.T) {
	tests := []struct {
		name string
		pdu  []byte
	}{
		{name: "BGP PDU shorter than minimum", pdu: []byte{1}},
		{name: "BGP length below minimum", pdu: func() []byte {
			pdu := routeMirrorTestBGPMessage(2, []byte{0, 0, 0, 0})
			binary.BigEndian.PutUint16(pdu[16:18], 18)
			return pdu
		}()},
		{name: "BGP length differs from TLV value", pdu: func() []byte {
			pdu := routeMirrorTestBGPMessage(2, []byte{0, 0, 0, 0})
			binary.BigEndian.PutUint16(pdu[16:18], uint16(len(pdu)+1))
			return pdu
		}()},
		{name: "truncated UPDATE body", pdu: routeMirrorTestBGPMessage(2, []byte{0})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := routeMirrorTestTLV(uint16(RouteMirrorBGPMsgTLV), tt.pdu)
			if _, err := UnmarshalBMPRouteMirrorMessage(wire); err == nil {
				t.Fatal("UnmarshalBMPRouteMirrorMessage() error = nil, want malformed BGP PDU error")
			}
		})
	}
}

func TestUnmarshalBMPRouteMirrorMessageFallsBackToTwoByteASPath(t *testing.T) {
	// The Route Mirroring A flag is not authoritative. This valid UPDATE has a
	// legacy two-byte AS_PATH, so the decoder's four-byte attempt must fail and
	// its two-byte retry must recover both ASNs.
	updateBody := []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x0d, // total path attribute length
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x02, 0xfc, 0x00, 0xfc, 0x01, // AS_PATH [64512, 64513]
	}
	pdu := routeMirrorTestBGPMessage(2, updateBody)
	wire := routeMirrorTestTLV(uint16(RouteMirrorBGPMsgTLV), pdu)
	got, err := UnmarshalBMPRouteMirrorMessage(wire)
	if err != nil {
		t.Fatalf("UnmarshalBMPRouteMirrorMessage() error = %v", err)
	}
	update, err := got.GetBGPUpdate()
	if err != nil {
		t.Fatalf("GetBGPUpdate() error = %v", err)
	}
	want := []uint32{64512, 64513}
	path := update.BaseAttributes.ASPath
	if len(path) != len(want) || path[0] != want[0] || path[1] != want[1] {
		t.Fatalf("AS_PATH = %v, want %v", path, want)
	}
}

func TestRouteMirrorSizeIncludesTLVHeadersAndValues(t *testing.T) {
	rm := &RouteMirror{TLVs: []TLV{
		{Type: RouteMirrorInfoTLV, Value: []byte{0, 1}},
		{Type: RouteMirrorBGPMsgTLV, Value: make([]byte, 19)},
	}}
	if got, want := rm.Size(), (4+2)+(4+19); got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}
}
