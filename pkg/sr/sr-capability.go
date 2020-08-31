package sr

import (
	"encoding/json"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Capability defines SR Capability object
// https://datatracker.ietf.org/doc/draft-ietf-idr-bgp-ls-segment-routing-ext/?include_text=1 Section 2.1.2
type Capability struct {
	Flags CapabilityFlags `json:"sr_capability_flags,omitempty"`
	TLV   []CapabilityTLV `json:"sr_capability_tlv,omitempty"`
}

// UnmarshalSRCapability builds SR Capability object
func UnmarshalSRCapability(protoID base.ProtoID, b []byte) (*Capability, error) {
	glog.V(6).Infof("SR Capability Raw: %s", tools.MessageHex(b))
	cap := Capability{}
	p := 0
	switch protoID {
	case base.ISISL1:
		fallthrough
	case base.ISISL2:
		cap.Flags = UnmarshalISISCapFlags(b[p])
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		cap.Flags = UnmarshalOSPFCapFlags(b[p])
	}
	p++
	// Skip reserved byte
	p++
	tlvs, err := UnmarshalSRCapabilityTLV(b[p:])
	if err != nil {
		return nil, err
	}
	cap.TLV = tlvs

	return &cap, nil
}

// BuildSRCapability builds SR Capability object from json.RawMessage
func BuildSRCapability(protoID base.ProtoID, b json.RawMessage) (*Capability, error) {
	cap := Capability{}
	var f map[string]json.RawMessage
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if v, ok := f["sr_capability_flags"]; ok {
		var fo map[string]json.RawMessage
		if err := json.Unmarshal(v, &fo); err != nil {
			return nil, err
		}
		switch protoID {
		case base.ISISL1:
			fallthrough
		case base.ISISL2:
			c, err := buildISISCapFlags(fo)
			if err != nil {
				return nil, err
			}
			cap.Flags = c
		case base.OSPFv2:
			fallthrough
		case base.OSPFv3:
			c, err := buildOSPFCapFlags(fo)
			if err != nil {
				return nil, err
			}
			cap.Flags = c
		}
	}
	cap.TLV = make([]CapabilityTLV, 0)
	if v, ok := f["sr_capability_tlv"]; ok {
		if err := json.Unmarshal(v, &cap.TLV); err != nil {
			return nil, err
		}
	}

	return &cap, nil
}

// CapabilityFlags used for "duck typing", SR Capability Flags are different for different protocols,
//  this interface will allow to integrate it in a common SR Capability structure.
type CapabilityFlags interface {
	MarshalJSON() ([]byte, error)
	capFlags()
}

//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |I|V|           |
// +-+-+-+-+-+-+-+-+
type isisCapFlags struct {
	I bool `json:"e_flag"`
	V bool `json:"v_flag"`
}

// ISISCapFlags defines methods to check ISIS Capabilities flags
type ISISCapFlags interface {
	IsI() bool
	IsV() bool
}

func (f *isisCapFlags) IsI() bool {
	return f.I
}

func (f *isisCapFlags) IsV() bool {
	return f.V
}

func (f *isisCapFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		I bool `json:"i_flag"`
		V bool `json:"v_flag"`
	}{
		I: f.I,
		V: f.V,
	})
}

func (f *isisCapFlags) capFlags() {
	// Function to avoind misuse of CapabilityFlags interface with different type of flags
}

// UnmarshalISISCapFlags constructs CapabilityFlags interface from Flags byte
func UnmarshalISISCapFlags(b byte) CapabilityFlags {
	f := &isisCapFlags{}
	f.I = b&0x80 == 0x80
	f.V = b&0x40 == 0x40

	return f
}

func buildISISCapFlags(fo map[string]json.RawMessage) (CapabilityFlags, error) {
	f := &isisCapFlags{}
	f.I = false
	if v, ok := fo["i_flag"]; ok {
		if err := json.Unmarshal(v, &f.I); err != nil {
			return nil, err
		}
	}
	f.V = false
	if v, ok := fo["v_flag"]; ok {
		if err := json.Unmarshal(v, &f.V); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// OSPFCapFlags defines methods to check OSPF Capabilities flags
type OSPFCapFlags interface {
}

// ospfCapFlags currently non defined
type ospfCapFlags struct {
}

func (f *ospfCapFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
	}{})
}

func (f *ospfCapFlags) capFlags() {
	// Function to avoind misuse of CapabilityFlags interface with different type of flags
}

// UnmarshalOSPFCapFlags constructs CapabilityFlags interface from Flags byte
func UnmarshalOSPFCapFlags(b byte) CapabilityFlags {
	f := &ospfCapFlags{}

	return f
}

func buildOSPFCapFlags(fo map[string]json.RawMessage) (CapabilityFlags, error) {
	f := &ospfCapFlags{}

	return f, nil
}
