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
		cap.Flags = unmarshalISISCapFlags(b[p])
	case base.OSPFv2:
		fallthrough
	case base.OSPFv3:
		cap.Flags = unmarshalOSPFCapFlags(b[p])
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

func (f *isisCapFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		I bool `json:"e_flag"`
		V bool `json:"v_flag"`
	}{
		I: f.I,
		V: f.V,
	})
}

func (f *isisCapFlags) capFlags() {
	// Function to avoind misuse of CapabilityFlags interface with different type of flags
}

func unmarshalISISCapFlags(b byte) CapabilityFlags {
	f := &isisCapFlags{}
	f.I = b&0x80 == 0x80
	f.V = b&0x40 == 0x40

	return f
}

// ospfCapFlags currently non defined
type ospfCapFlags struct {
}

func (f *ospfCapFlags) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (f *ospfCapFlags) capFlags() {
	// Function to avoind misuse of CapabilityFlags interface with different type of flags
}

func unmarshalOSPFCapFlags(b byte) CapabilityFlags {
	f := &ospfCapFlags{}

	return f
}
