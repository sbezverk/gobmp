package base

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// PrefixAttrFlags used for "duck typing", Prefix attribute Flags are different for different protocols,
//  this interface will allow to integrate it in a common PrefixAttributeFlags structure.
type PrefixAttrFlags interface {
	MarshalJSON() ([]byte, error)
}

// UnmarshalPrefixAttrFlagsTLV builds Prefix attributes flags object
func UnmarshalPrefixAttrFlagsTLV(protoID ProtoID, b []byte) (PrefixAttrFlags, error) {
	glog.V(6).Infof("Prefix Attribute Flags Raw: %s", tools.MessageHex(b))

	switch protoID {
	case ISISL1:
		fallthrough
	case ISISL2:
		return UnmarshalISISFlags(b[0]), nil
	case OSPFv2:
		return UnmarshalOSPFv2Flags(b[0]), nil
	case OSPFv3:
		return UnmarshalOSPFv3Flags(b[0]), nil
	default:
		return nil, fmt.Errorf("unknown protocol id: %d", protoID)
	}
}

//  0 1 2 3 4 5 6 7...
// +-+-+-+-+-+-+-+-+...
// |X|R|N|          ...
// +-+-+-+-+-+-+-+-+...
type isisFlags struct {
	X bool `json:"x_flag"`
	R bool `json:"r_flag"`
	N bool `json:"n_flag"`
}

func (f *isisFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		X bool `json:"x_flag"`
		R bool `json:"r_flag"`
		N bool `json:"n_flag"`
	}{
		X: f.X,
		R: f.R,
		N: f.N,
	})
}

func UnmarshalISISFlags(b byte) PrefixAttrFlags {
	f := &isisFlags{}
	f.X = b&0x80 == 0x80
	f.R = b&0x40 == 0x40
	f.N = b&0x20 == 0x20

	return f
}

// 0x80 - A-Flag (Attach Flag)
// 0x40 - N-Flag (Node Flag)
type ospfv2Flags struct {
	A bool `json:"a_flag"`
	N bool `json:"n_flag"`
}

func (f *ospfv2Flags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		A bool `json:"a_flag"`
		N bool `json:"n_flag"`
	}{
		A: f.A,
		N: f.N,
	})
}

func UnmarshalOSPFv2Flags(b byte) PrefixAttrFlags {
	f := &ospfv2Flags{}
	f.A = b&0x80 == 0x80
	f.N = b&0x40 == 0x40

	return f
}

//  0  1  2  3  4  5  6  7
// +--+--+--+--+--+--+--+--+
// |  |  | N|DN| P| x|LA|NU|
// +--+--+--+--+--+--+--+--+
type ospfv3Flags struct {
	N  bool `json:"n_flag"`
	DN bool `json:"dn_flag"`
	P  bool `json:"p_flag"`
	X  bool `json:"x_flag"`
	LA bool `json:"la_flag"`
	NU bool `json:"nu_flag"`
}

func (f *ospfv3Flags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		N  bool `json:"n_flag"`
		DN bool `json:"dn_flag"`
		P  bool `json:"p_flag"`
		X  bool `json:"x_flag"`
		LA bool `json:"la_flag"`
		NU bool `json:"nu_flag"`
	}{
		N:  f.N,
		DN: f.DN,
		P:  f.P,
		X:  f.X,
		LA: f.LA,
		NU: f.NU,
	})
}

func UnmarshalOSPFv3Flags(b byte) PrefixAttrFlags {
	f := &ospfv3Flags{}
	f.N = b&0x20 == 0x20
	f.DN = b&0x10 == 0x10
	f.P = b&0x08 == 0x08
	f.X = b&0x04 == 0x04
	f.LA = b&0x02 == 0x02
	f.NU = b&0x01 == 0x01

	return f
}
