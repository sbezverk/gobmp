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

func TestRouteMirrorSizeIncludesTLVHeadersAndValues(t *testing.T) {
	rm := &RouteMirror{TLVs: []TLV{
		{Type: RouteMirrorInfoTLV, Value: []byte{0, 1}},
		{Type: RouteMirrorBGPMsgTLV, Value: make([]byte, 19)},
	}}
	if got, want := rm.Size(), (4+2)+(4+19); got != want {
		t.Fatalf("Size() = %d, want %d", got, want)
	}
}
