package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/sr"
)

func TestLSNodeRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		original *LSNode
	}{
		{
			name: "protocol_id_1",
			original: &LSNode{
				ProtocolID: 1,
				SRCapabilities: &sr.Capability{
					Flags: sr.UnmarshalISISCapFlags(0x80),
					TLV:   make([]sr.CapabilityTLV, 0),
				},
			},
		},
		{
			name: "protocol_id_3",
			original: &LSNode{
				ProtocolID: 3,
				SRCapabilities: &sr.Capability{
					Flags: sr.UnmarshalOSPFCapFlags(0x80),
					TLV:   make([]sr.CapabilityTLV, 0),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.original)
			if err != nil {
				t.Errorf("failed to marshal with error: %+v", err)
			}
			result := &LSNode{}
			if err := json.Unmarshal(b, result); err != nil {
				t.Errorf("failed to unmarshal with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.original, result) {
				t.Error("original LSNode does not match resulting one")
			}
			switch result.ProtocolID {
			case base.ISISL1:
				fallthrough
			case base.ISISL2:
				if _, ok := result.SRCapabilities.Flags.(sr.ISISCapFlags); !ok {
					t.Error("failed to recover ISIS Capabilities interface")
				}
			case base.OSPFv2:
				fallthrough
			case base.OSPFv3:
				if _, ok := result.SRCapabilities.Flags.(sr.OSPFCapFlags); !ok {
					t.Error("failed to recover OSPF Capabilities interface")
				}
			}
		})
	}
}

func TestLSLinkRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		original *LSLink
	}{
		{
			name: "protocol_id_1",
			original: &LSLink{
				ProtocolID: 1,
			},
		},
		{
			name: "protocol_id_3",
			original: &LSLink{
				ProtocolID: 3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.original)
			if err != nil {
				t.Errorf("failed to marshal with error: %+v", err)
			}
			result := &LSLink{}
			if err := json.Unmarshal(b, result); err != nil {
				t.Errorf("failed to unmarshal with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.original, result) {
				t.Error("original LSNode does not match resulting one")
			}
			switch result.ProtocolID {
			case base.ISISL1:
				fallthrough
			case base.ISISL2:
			case base.OSPFv2:
				fallthrough
			case base.OSPFv3:
			}
		})
	}
}

func TestLSPrefixRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		original *LSPrefix
	}{
		{
			name: "protocol id isis l1",
			original: &LSPrefix{
				ProtocolID:      base.ISISL1,
				PrefixAttrFlags: base.UnmarshalISISFlags(0x80),
				LSPrefixSID: []*sr.PrefixSIDTLV{
					{
						Flags: sr.UnmarshalPrefixSIDISISFlags(0x80),
						SID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					},
				},
			},
		},
		{
			name: "protocol id isis l2",
			original: &LSPrefix{
				ProtocolID:      base.ISISL2,
				PrefixAttrFlags: base.UnmarshalISISFlags(0x80),
				LSPrefixSID: []*sr.PrefixSIDTLV{
					{
						Flags: sr.UnmarshalPrefixSIDISISFlags(0x80),
						SID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					},
				},
			},
		},
		{
			name: "protocol id ospf v2",
			original: &LSPrefix{
				ProtocolID:      base.OSPFv2,
				PrefixAttrFlags: base.UnmarshalOSPFv2Flags(0x80),
				LSPrefixSID: []*sr.PrefixSIDTLV{
					{
						Flags: sr.UnmarshalPrefixSIDOSPFFlags(0x80),
						SID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					},
				},
			},
		},
		{
			name: "protocol id ospf v3",
			original: &LSPrefix{
				ProtocolID:      base.OSPFv3,
				PrefixAttrFlags: base.UnmarshalOSPFv3Flags(0x80),
				LSPrefixSID: []*sr.PrefixSIDTLV{
					{
						Flags: sr.UnmarshalPrefixSIDOSPFFlags(0x80),
						SID:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.original)
			if err != nil {
				t.Errorf("failed to marshal with error: %+v", err)
			}
			result := &LSPrefix{}
			if err := json.Unmarshal(b, result); err != nil {
				t.Errorf("failed to unmarshal with error: %+v", err)
			}
			if !reflect.DeepEqual(tt.original, result) {
				t.Error("original LSNode does not match resulting one")
			}
			switch result.ProtocolID {
			case base.ISISL1:
				fallthrough
			case base.ISISL2:
				if _, ok := result.PrefixAttrFlags.(base.ISISPrefixAttrFlags); !ok {
					t.Error("failed to recover ISIS Prefix Attribute Flags interface")
				}
			case base.OSPFv2:
				if _, ok := result.PrefixAttrFlags.(base.OSPFv2PrefixAttrFlags); !ok {
					t.Error("failed to recover OSPFv2 Prefix Attribute Flags interface")
				}
			case base.OSPFv3:
				if _, ok := result.PrefixAttrFlags.(base.OSPFv3PrefixAttrFlags); !ok {
					t.Error("failed to recover OSPFv3 Prefix Attribute Flags interface")
				}
			}
			// Testing if Flags interface can be recovered from Prefix SID object
			for _, psid := range result.LSPrefixSID {
				switch result.ProtocolID {
				case base.ISISL1:
					fallthrough
				case base.ISISL2:
					if _, ok := psid.Flags.(sr.PrefixSIDISISFlags); !ok {
						t.Error("failed to recover ISIS Prefix SID Flags interface")
					}
				case base.OSPFv2:
					fallthrough
				case base.OSPFv3:
					if _, ok := psid.Flags.(sr.PrefixSIDOSPFFlags); !ok {
						t.Error("failed to recover OSPF Prefix SID Flags interface")
					}
				}
			}
		})
	}
}
