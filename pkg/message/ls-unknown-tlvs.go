package message

import (
	"encoding/hex"

	"github.com/sbezverk/gobmp/pkg/bgpls"
)

// collectUnknownBGPLSTLVs retains the wire order of unmapped top-level TLVs.
// Recognition depends on the type and event mapping, regardless of value
// decoding or which of several supported values supplies a field.
func collectUnknownBGPLSTLVs(tlvs []bgpls.TLV, isModeled func(uint16) bool) []UnknownBGPLSTLV {
	var unknown []UnknownBGPLSTLV
	for _, tlv := range tlvs {
		if isModeled(tlv.Type) {
			continue
		}
		unknown = append(unknown, UnknownBGPLSTLV{
			Type:     tlv.Type,
			ValueHex: hex.EncodeToString(tlv.Value),
		})
	}
	return unknown
}
