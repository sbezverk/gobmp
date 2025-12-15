package message

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/vpls"
)

// vpls process MP_REACH_NLRI AFI 25 SAFI 65 update message and returns
// VPLS prefix object.
func (p *producer) vpls(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]VPLSPrefix, error) {
	if glog.V(6) {
		glog.Infof("All attributes in vpls update: %+v", update.GetAllAttributeID())
	}
	vpls, err := nlri.GetNLRIVPLS()
	if err != nil {
		return nil, err
	}
	prfxs := make([]VPLSPrefix, 0)
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	for _, v := range vpls.Route {
		prfx := VPLSPrefix{
			Action:         operation,
			PeerType:       uint8(ph.PeerType),
			RouterHash:     p.speakerHash,
			RouterIP:       p.speakerIP,
			PeerHash:       ph.GetPeerHash(),
			PeerASN:        ph.PeerAS,
			Timestamp:      ph.GetPeerTimestamp(),
			Nexthop:        nlri.GetNextHop(),
			BaseAttributes: update.BaseAttributes,
		}
		if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
			// Last element in AS_PATH would be the AS of the origin
			prfx.OriginAS = ases[len(ases)-1]
		}

		prfx.PeerIP = ph.GetPeerAddrString()
		prfx.RemoteBGPID = ph.GetPeerBGPIDString()
		prfx.IsIPv4 = !nlri.IsIPv6NLRI()
		prfx.IsNexthopIPv4 = !nlri.IsNextHopIPv6()

		// Do not want to panic on nil pointer
		if v != nil && v.RD != nil {
			prfx.VPNRD = v.RD.String()
			prfx.RFCType = v.RFCType

			// RFC 4761 specific fields (17-byte NLRI)
			if v.RFCType == "RFC4761" {
				if v.VEID != nil {
					prfx.VEID = v.VEID
				}
				if v.VEBlockOffset != nil {
					prfx.VEBlockOffset = v.VEBlockOffset
				}
				if v.VEBlockSize != nil {
					prfx.VEBlockSize = v.VEBlockSize
				}
				if v.LabelBase != nil {
					prfx.LabelBase = v.LabelBase
					// Calculate label block end
					labelStart, labelEnd := v.GetLabelRange()
					prfx.LabelBlockEnd = &labelEnd
					if glog.V(6) {
						glog.Infof("RFC 4761 VPLS: VE ID=%d, Label range=%d-%d",
							*v.VEID, labelStart, labelEnd)
					}
				}
			}

			// RFC 6074 specific fields (12-byte NLRI)
			if v.RFCType == "RFC6074" {
				peAddr := v.GetPEAddress()
				if peAddr != "" {
					prfx.PEAddress = &peAddr
				}
				if glog.V(6) {
					glog.Infof("RFC 6074 BGP-AD: PE Address=%s", peAddr)
				}
			}
		}

		// Parse Extended Communities (Type 16)
		// This is common to both RFC 4761 and RFC 6074
		// Parse both Layer2 Info (Type 0x800A) and Route Target (Type 0x0002, 0x0102, 0x0202)
		for _, attr := range update.PathAttributes {
			if attr.AttributeType == 16 {
				// Parse Extended Community (8-byte chunks)
				extCommData := attr.Attribute
				routeTargets := make([]string, 0)

				for i := 0; i+8 <= len(extCommData); i += 8 {
					ec := extCommData[i : i+8]
					ecType := uint16(ec[0])<<8 | uint16(ec[1])

					// Check for Layer2 Info Extended Community (Type 0x800A)
					if ec[0] == 0x80 && ec[1] == 0x0a {
						// Encapsulation Type (byte 2)
						encapType := ec[2]
						encapStr := getEncapTypeString(encapType)
						prfx.EncapType = &encapStr

						// Control Flags (byte 3)
						flags := ec[3]
						controlWord := (flags & 0x01) != 0
						sequencedDel := (flags & 0x02) != 0
						prfx.ControlWord = &controlWord
						prfx.SequencedDel = &sequencedDel

						// MTU (bytes 4-5)
						mtu := uint16(ec[4])<<8 | uint16(ec[5])
						prfx.MTU = &mtu

						if glog.V(6) {
							glog.Infof("Layer2 Info ExtComm: Encap=%s, C=%t, S=%t, MTU=%d",
								encapStr, controlWord, sequencedDel, mtu)
						}
					}

					// Check for Route Target Extended Community (Type 0x0002, 0x0102, 0x0202)
					if ecType == 0x0002 || ecType == 0x0102 || ecType == 0x0202 {
						// Import vpls package locally for RT parsing
						rtStr := parseRouteTargetString(ec)
						if rtStr != "" {
							routeTargets = append(routeTargets, rtStr)
							if glog.V(6) {
								glog.Infof("Route Target ExtComm: %s", rtStr)
							}
						}
					}
				}

				// Assign Route Targets if any were found
				if len(routeTargets) > 0 {
					prfx.RouteTargets = routeTargets
				}
				break
			}
		}

		prfxs = append(prfxs, prfx)
	}

	return prfxs, nil
}

// getEncapTypeString returns human-readable encapsulation type string
func getEncapTypeString(encapType uint8) string {
	switch encapType {
	case 1:
		return "Frame Relay DLCI"
	case 2:
		return "ATM AAL5 VCC transport"
	case 3:
		return "ATM transparent cell transport"
	case 4:
		return "Ethernet (802.3)"
	case 5:
		return "VLAN (802.1Q)"
	case 6:
		return "HDLC"
	case 7:
		return "PPP"
	case 8:
		return "SONET/SDH Circuit Emulation Service"
	case 9:
		return "ATM n-to-one VCC cell transport"
	case 10:
		return "ATM n-to-one VPC cell transport"
	case 11:
		return "IP Layer 2 Transport"
	case 19:
		return "Ethernet VLAN (802.1Q)"
	default:
		return fmt.Sprintf("Unknown (%d)", encapType)
	}
}

// parseRouteTargetString parses Route Target Extended Community and returns string representation
// Input: 8-byte extended community value
// Returns: RT string (e.g., "RT:65000:100") or empty string on error
func parseRouteTargetString(b []byte) string {
	rt, err := vpls.ParseRouteTarget(b)
	if err != nil {
		if glog.V(6) {
			glog.Warningf("Failed to parse Route Target: %v", err)
		}
		return ""
	}
	return rt.String()
}
