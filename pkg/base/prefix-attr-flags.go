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
	ISISL1PrefixAttrFlags
}

// UnmarshalPrefixAttrFlagsTLV builds Prefix attributes flags object
func UnmarshalPrefixAttrFlagsTLV(protoID ProtoID, b []byte) (PrefixAttrFlags, error) {
	glog.V(6).Infof("Prefix Attribute Flags Raw: %s", tools.MessageHex(b))

	switch protoID {
	case ISISL1:
		fallthrough
	case ISISL2:
		return unmarshalISISFlags(b[0]), nil
	case OSPFv2:
		return unmarshalOSPFv2Flags(b[0]), nil
	case OSPFv3:
		return unmarshalOSPFv3Flags(b[0]), nil
	default:
		return nil, fmt.Errorf("unknown protocol id: %d", protoID)
	}
}

// BuildPrefixAttrFlags builds Prefix attributes flags object from json RawMessage
func BuildPrefixAttrFlags(protoID ProtoID, b json.RawMessage) (PrefixAttrFlags, error) {
	var f map[string]json.RawMessage
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}

	switch protoID {
	case ISISL1:
		fallthrough
	case ISISL2:
		return buildISISFlags(f)
	case OSPFv2:
		return buildOSPFv2Flags(f)
	case OSPFv3:
		return buildOSPFv3Flags(f)
	default:
		return nil, fmt.Errorf("unknown protocol id: %d", protoID)
	}
}

// ISISL1PrefixAttrFlags defines methods to test ISIS L1 prefix attribute flags
type ISISL1PrefixAttrFlags interface {
	IsX() bool
	IsR() bool
	IsN() bool
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

func unmarshalISISFlags(b byte) PrefixAttrFlags {
	f := &isisFlags{}
	f.X = b&0x80 == 0x80
	f.R = b&0x40 == 0x40
	f.N = b&0x20 == 0x20

	return f
}

func buildISISFlags(b map[string]json.RawMessage) (PrefixAttrFlags, error) {
	f := &isisFlags{}

	f.X = false
	if v, ok := b["x_flag"]; ok {
		if err := json.Unmarshal(v, &f.X); err != nil {
			return nil, err
		}
	}
	f.R = false
	if v, ok := b["r_flag"]; ok {
		if err := json.Unmarshal(v, &f.R); err != nil {
			return nil, err
		}
	}
	f.N = false
	if v, ok := b["n_flag"]; ok {
		if err := json.Unmarshal(v, &f.N); err != nil {
			return nil, err
		}
	}

	return f, nil
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

func unmarshalOSPFv2Flags(b byte) PrefixAttrFlags {
	f := &ospfv2Flags{}
	f.A = b&0x80 == 0x80
	f.N = b&0x40 == 0x40

	return f
}

func buildOSPFv2Flags(b map[string]json.RawMessage) (PrefixAttrFlags, error) {
	f := &ospfv2Flags{}

	f.A = false
	if v, ok := b["a_flag"]; ok {
		if err := json.Unmarshal(v, &f.A); err != nil {
			return nil, err
		}
	}
	f.N = false
	if v, ok := b["n_flag"]; ok {
		if err := json.Unmarshal(v, &f.N); err != nil {
			return nil, err
		}
	}

	return f, nil
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

func unmarshalOSPFv3Flags(b byte) PrefixAttrFlags {
	f := &ospfv3Flags{}
	f.N = b&0x20 == 0x20
	f.DN = b&0x10 == 0x10
	f.P = b&0x08 == 0x08
	f.X = b&0x04 == 0x04
	f.LA = b&0x02 == 0x02
	f.NU = b&0x01 == 0x01

	return f
}

func buildOSPFv3Flags(b map[string]json.RawMessage) (PrefixAttrFlags, error) {
	f := &ospfv3Flags{}

	f.N = false
	if v, ok := b["n_flag"]; ok {
		if err := json.Unmarshal(v, &f.N); err != nil {
			return nil, err
		}
	}
	f.DN = false
	if v, ok := b["dn_flag"]; ok {
		if err := json.Unmarshal(v, &f.DN); err != nil {
			return nil, err
		}
	}
	f.P = false
	if v, ok := b["p_flag"]; ok {
		if err := json.Unmarshal(v, &f.P); err != nil {
			return nil, err
		}
	}
	f.X = false
	if v, ok := b["x_flag"]; ok {
		if err := json.Unmarshal(v, &f.X); err != nil {
			return nil, err
		}
	}
	f.LA = false
	if v, ok := b["la_flag"]; ok {
		if err := json.Unmarshal(v, &f.LA); err != nil {
			return nil, err
		}
	}
	f.NU = false
	if v, ok := b["nu_flag"]; ok {
		if err := json.Unmarshal(v, &f.NU); err != nil {
			return nil, err
		}
	}

	return f, nil
}
