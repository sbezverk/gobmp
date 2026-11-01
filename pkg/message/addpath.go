package message

import (
	"encoding/binary"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

type peerAddPathProperties struct {
	in  map[bgp.AFISAFI]bool
	out map[bgp.AFISAFI]bool
}

// setPeerProperties publishes new maps rather than mutating a map that route
// workers might still be reading from the preceding Peer Up.
func (p *producer) setPeerProperties(ph *bmp.PerPeerHeader, up *bmp.PeerUpMessage) peerAddPathProperties {
	local, remote := up.SentOpen.AddPathModes(), up.ReceivedOpen.AddPathModes()
	properties := peerAddPathProperties{
		in:  make(map[bgp.AFISAFI]bool, len(local)),
		out: make(map[bgp.AFISAFI]bool, len(local)),
	}
	p.tableLock.Lock()
	defer p.tableLock.Unlock()
	if ph.PeerType == bmp.PeerType3 {
		// RFC 9069 Sections 5.2 and 6.1.1: fabricated OPENs describe the
		// Loc-RIB encoding; separate Peer Ups may describe different families.
		// Replace only declared families, including clearing ADD-PATH when a
		// family is repeated without it, and preserve all other families.
		for family, enabled := range p.peerAddPath[ph.PeerIdentity()].in {
			properties.in[family] = enabled
		}
		for _, capability := range up.SentOpen.Capabilities[1] {
			if capability != nil && len(capability.Value) == 4 {
				family := bgp.AFISAFI{AFI: binary.BigEndian.Uint16(capability.Value[:2]), SAFI: capability.Value[3]}
				properties.in[family] = false
			}
		}
		for family := range local {
			properties.in[family] = true
		}
		p.tableProperties[ph.GetTableKey()] = PerTableProperties{
			tableInfoTLVs: append([]bmp.InformationalTLV(nil), up.Information...),
		}
	} else {
		for family, mode := range local {
			properties.in[family] = mode&1 != 0 && remote[family]&2 != 0
			properties.out[family] = mode&2 != 0 && remote[family]&1 != 0
		}
	}
	p.peerAddPath[ph.PeerIdentity()] = properties
	return properties
}

func (p *producer) addPathEnabled(ph *bmp.PerPeerHeader, family bgp.AFISAFI) bool {
	if ph == nil {
		return false
	}
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()
	properties := p.peerAddPath[ph.PeerIdentity()]
	if outbound, err := ph.IsAdjRIBOut(); err == nil && outbound {
		return properties.out[family]
	}
	return properties.in[family]
}

func (p *producer) mpAddPathCapability(ph *bmp.PerPeerHeader, attribute []byte) map[int]bool {
	if len(attribute) < 3 {
		return nil // The MP parser reports the malformed attribute.
	}
	family := bgp.AFISAFI{AFI: binary.BigEndian.Uint16(attribute[:2]), SAFI: attribute[2]}
	if !p.addPathEnabled(ph, family) {
		return nil
	}
	// The existing MP decoder API uses output message types as map keys.
	// Translate only this attribute's family so colliding output types cannot
	// leak negotiation between IPv4/IPv6 or VPN/non-VPN FlowSpec.
	return map[int]bool{bgp.NLRIMessageType(family.AFI, family.SAFI): true}
}
