package sr

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// CapabilityFlags defines PrefixSID Flag interface
type CapabilityFlags interface {
	GetCapabilityFlagByte() byte
}

// Capability defines SR Capability object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ls-segment-routing-ext/?include_text=1 Section 2.1.2
type Capability struct {
	Flags  CapabilityFlags    `json:"flags,omitempty"`
	SubTLV []CapabilitySubTLV `json:"sr_capability_subtlv,omitempty"`
}

func (c *Capability) MarshalJSON() ([]byte, error) {
	switch c.Flags.(type) {
	case *ISISCapFlags:
		f := c.Flags.(*ISISCapFlags)
		return json.Marshal(struct {
			Flags  *ISISCapFlags      `json:"flags,omitempty"`
			SubTLV []CapabilitySubTLV `json:"sr_capability_subtlv,omitempty"`
		}{
			Flags:  f,
			SubTLV: c.SubTLV,
		})
	case *UnknownProtoFlags:
		f := c.Flags.(*UnknownProtoFlags)
		return json.Marshal(struct {
			Flags  *UnknownProtoFlags `json:"flags,omitempty"`
			SubTLV []CapabilitySubTLV `json:"sr_capability_subtlv,omitempty"`
		}{
			Flags:  f,
			SubTLV: c.SubTLV,
		})
	default:
		return json.Marshal(struct {
			SubTLV []CapabilitySubTLV `json:"sr_capability_subtlv,omitempty"`
		}{
			SubTLV: c.SubTLV,
		})
	}
}

func (c *Capability) UnmarshalJSON(b []byte) error {
	result := &Capability{}
	var objVal map[string]json.RawMessage
	if err := json.Unmarshal(b, &objVal); err != nil {
		return err
	}
	// Flags  CapabilityFlags    `json:"flags,omitempty"`
	if v, ok := objVal["flags"]; ok {
		var flags interface{}
		if err := json.Unmarshal(v, &flags); err != nil {
			return err
		}
		if _, ok := flags.(map[string]interface{})["i_flag"]; ok {
			// ISIS flags
			f := &ISISCapFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		} else {
			f := &UnknownProtoFlags{}
			if err := json.Unmarshal(v, &f); err != nil {
				return err
			}
			result.Flags = f
		}
	}
	// SubTLV []CapabilitySubTLV `json:"sr_capability_subtlv,omitempty"`
	if v, ok := objVal["sr_capability_subtlv"]; ok {
		if err := json.Unmarshal(v, &result.SubTLV); err != nil {
			return err
		}
	}

	*c = *result

	return nil
}

// UnmarshalSRCapability builds SR Capability object
func UnmarshalSRCapability(b []byte, proto base.ProtoID) (*Capability, error) {
	if glog.V(6) {
		glog.Infof("SR Capability Raw: %s", tools.MessageHex(b))
	}
	cap := Capability{}
	p := 0
	switch proto {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		f, err := UnmarshalISISCapFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		cap.Flags = f
	default:
		f, err := UnmarshalUnknownProtoFlags(b[p : p+1])
		if err != nil {
			return nil, err
		}
		cap.Flags = f
	}
	p++
	// Skip reserved byte
	p++
	tlvs, err := UnmarshalSRCapabilitySubTLV(b[p:])
	if err != nil {
		return nil, err
	}
	cap.SubTLV = tlvs

	return &cap, nil
}

//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |I|V|           |
// +-+-+-+-+-+-+-+-+
// ISISFlags defines a structure of ISIS Prefix SID flags
type ISISCapFlags struct {
	IFlag bool `json:"i_flag"`
	VFlag bool `json:"v_flag"`
}

// UnmarshalISISFlags build Prefix SID ISIS Flag Object
func UnmarshalISISCapFlags(b []byte) (*ISISCapFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SR Capability ISIS Flags")
	}
	nf := &ISISCapFlags{}
	nf.IFlag = b[0]&0x80 == 0x80
	nf.VFlag = b[0]&0x40 == 0x40

	return nf, nil
}

//GetCapabilityFlagByte returns a byte represenation for ISIS flags
func (f *ISISCapFlags) GetCapabilityFlagByte() byte {
	b := byte(0)
	if f.IFlag {
		b += 0x80
	}
	if f.VFlag {
		b += 0x40
	}

	return b
}

//GetCapabilityFlagByte returns a byte represenation for OSPF flags
func (f *UnknownProtoFlags) GetCapabilityFlagByte() byte {
	return f.Flags
}
