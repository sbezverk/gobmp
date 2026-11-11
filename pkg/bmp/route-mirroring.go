package bmp

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

type RouteMirrorTLVType uint16

const (
	RouteMirrorBGPMsgTLV RouteMirrorTLVType = 0
	RouteMirrorInfoTLV   RouteMirrorTLVType = 1
)

type RouteMirrorTLVInfoCode uint16

const (
	RouteMirrorInfoCodeErrored RouteMirrorTLVInfoCode = 0
	RouteMirrorInfoCodeLost    RouteMirrorTLVInfoCode = 1
)

type TLV struct {
	Type   RouteMirrorTLVType
	Length uint16
	Value  []byte
}

type RouteMirror struct {
	TLVs   []TLV
	update *bgp.Update
}

func (rm *RouteMirror) Size() int {
	size := 0
	for _, tlv := range rm.TLVs {
		size += 4 // TLV header
		size += len(tlv.Value)
	}

	return size
}

func (rm *RouteMirror) GetBGPUpdate() (*bgp.Update, error) {
	if rm.update != nil {
		return rm.update, nil
	}
	for _, tlv := range rm.TLVs {
		if tlv.Type == RouteMirrorInfoTLV {
			// Info TLV must have at least 2 bytes length for the Info Code
			if tlv.Length < 2 {
				return nil, fmt.Errorf("invalid Info TLV length")
			}
			if len(tlv.Value) < 2 {
				return nil, fmt.Errorf("invalid Info TLV value length")
			}
			code := binary.BigEndian.Uint16(tlv.Value[:2])
			switch RouteMirrorTLVInfoCode(code) {
			case RouteMirrorInfoCodeErrored:
				return nil, fmt.Errorf("indicates Info TLV \"errored\"")
			case RouteMirrorInfoCodeLost:
				return nil, fmt.Errorf("indicates Info TLV \"lost\"")
			default:
				return nil, fmt.Errorf("unknown Info TLV code: %d", code)
			}
		}
	}

	return nil, fmt.Errorf("bgp update is not available")
}

func UnmarshalBMPRouteMirrorMessage(b []byte) (*RouteMirror, error) {
	return unmarshalRouteMirror(b, nil)
}

func unmarshalRouteMirror(b []byte, isAS4 *bool) (*RouteMirror, error) {
	if glog.V(6) {
		glog.Infof("BMP Route Mirror Message Raw: %s length: %d", tools.MessageHex(b), len(b))
	}
	if len(b) < 4 {
		return nil, fmt.Errorf("route mirror message too short: need at lest 4 bytes, have %d", len(b))
	}
	rm := &RouteMirror{
		TLVs:   make([]TLV, 0),
		update: nil,
	}
	p := 0
	for i := 0; p < len(b); i++ {
		if len(b[p:]) < 4 {
			return nil, fmt.Errorf("route mirror TLV header too short: need 4 bytes, have %d", len(b[p:]))
		}
		t := RouteMirrorTLVType(binary.BigEndian.Uint16(b[p : p+2]))
		l := binary.BigEndian.Uint16(b[p+2 : p+4])
		p += 4
		if len(b[p:]) < int(l) {
			return nil, fmt.Errorf("message length mismatch: header says %d bytes, have %d", l, len(b[p:]))
		}
		rm.TLVs = append(rm.TLVs, TLV{
			Type:   t,
			Length: l,
			Value:  make([]byte, l),
		})
		copy(rm.TLVs[i].Value, b[p:p+int(l)])
		p += int(l)
	}

	for i, tlv := range rm.TLVs {
		if tlv.Type == RouteMirrorBGPMsgTLV && i != len(rm.TLVs)-1 {
			return nil, fmt.Errorf("BGP Message TLV must be last in Route Mirror message")
		}
	}
	tryAS4 := true
	for _, tlv := range rm.TLVs {
		if tlv.Type == RouteMirrorBGPMsgTLV {
			u, err := getBGPUpdateFromBMPMessage(tlv.Value, &tryAS4)
			if err != nil && !errors.Is(err, ErrNotAnUpdate) {
				// Attempt to retry with AS4 hint set to false if the first attempt fails
				tryAS4 = false
				u, err = getBGPUpdateFromBMPMessage(tlv.Value, &tryAS4)
				if err != nil {
					return nil, err
				}
			} else if err != nil {
				return nil, err
			}
			rm.update = u
			break
		}
	}

	return rm, nil
}

func getBGPUpdateFromBMPMessage(b []byte, as4hint *bool) (*bgp.Update, error) {
	// 16 bytes marker + 2 bytes length + 1 byte type
	if len(b) < 19 {
		return nil, fmt.Errorf("route monitor message too short: need 19 bytes, have %d", len(b))
	}
	p := 0
	// Skip 16 bytes of a marker
	p += 16
	// Validate BGP message length field
	bgpLen := binary.BigEndian.Uint16(b[p : p+2])
	if int(bgpLen) < 19 {
		return nil, fmt.Errorf("invalid BGP message length %d: must be >= 19", bgpLen)
	}
	if int(bgpLen) != len(b) {
		return nil, fmt.Errorf("BGP message length mismatch: header says %d bytes, have %d", bgpLen, len(b))
	}
	p += 2
	t := b[p]
	p++
	switch t {
	case 2:
		var (
			u   *bgp.Update
			err error
		)
		if as4hint != nil {
			u, err = bgp.UnmarshalBGPUpdateWithAS4Hint(b[p:], *as4hint)
		} else {
			u, err = bgp.UnmarshalBGPUpdate(b[p:])
		}
		if err != nil {
			return nil, err
		}
		return u, nil
	default:
		return nil, fmt.Errorf("%w: got type %d", ErrNotAnUpdate, t)
	}
}
