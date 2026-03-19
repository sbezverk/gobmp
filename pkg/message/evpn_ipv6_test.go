package message

import (
	"encoding/binary"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/evpn"
	"github.com/sbezverk/gobmp/pkg/flowspec"
	"github.com/sbezverk/gobmp/pkg/ls"
	"github.com/sbezverk/gobmp/pkg/mcastvpn"
	"github.com/sbezverk/gobmp/pkg/rtc"
	"github.com/sbezverk/gobmp/pkg/srpolicy"
	"github.com/sbezverk/gobmp/pkg/vpls"
)

type evpnMockNLRI struct {
	route   *evpn.Route
	nextHop string
	isIPv6  bool
}

func (m *evpnMockNLRI) GetAFISAFIType() int                            { return 24 }
func (m *evpnMockNLRI) GetNLRILU() (*base.MPNLRI, error)               { return nil, nil }
func (m *evpnMockNLRI) GetNLRIUnicast() (*base.MPNLRI, error)          { return nil, nil }
func (m *evpnMockNLRI) GetNLRIMulticast() (*base.MPNLRI, error)        { return nil, nil }
func (m *evpnMockNLRI) GetNLRIEVPN() (*evpn.Route, error)              { return m.route, nil }
func (m *evpnMockNLRI) GetNLRIVPLS() (*vpls.Route, error)              { return nil, nil }
func (m *evpnMockNLRI) GetNLRIL3VPN() (*base.MPNLRI, error)            { return nil, nil }
func (m *evpnMockNLRI) GetNLRI71() (*ls.NLRI71, error)                 { return nil, nil }
func (m *evpnMockNLRI) GetNLRI73() (*srpolicy.NLRI73, error)           { return nil, nil }
func (m *evpnMockNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error)       { return nil, nil }
func (m *evpnMockNLRI) GetAllFlowspecNLRI() ([]*flowspec.NLRI, error)  { return nil, nil }
func (m *evpnMockNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error)      { return nil, nil }
func (m *evpnMockNLRI) GetNLRIMVPN() (*mcastvpn.Route, error)          { return nil, nil }
func (m *evpnMockNLRI) GetNLRIRTC() (*rtc.Route, error)                { return nil, nil }
func (m *evpnMockNLRI) GetNextHop() string                             { return m.nextHop }
func (m *evpnMockNLRI) IsIPv6NLRI() bool                               { return m.isIPv6 }
func (m *evpnMockNLRI) IsNextHopIPv6() bool                            { return m.isIPv6 }

func buildEVPNType5IPv6Wire() []byte {
	// EVPN Type 5 IPv6: RD(8)+ESI(10)+EthTag(4)+IPLen(1)+IPv6(16)+GW(16)+Label(3) = 58
	wire := make([]byte, 58)
	off := 0
	// RD type 0
	binary.BigEndian.PutUint16(wire[off:], 0)
	off += 2
	binary.BigEndian.PutUint16(wire[off:], 0)
	off += 2
	binary.BigEndian.PutUint32(wire[off:], 100)
	off += 4
	// ESI: zeros
	off += 10
	// EthTag: 0
	off += 4
	// IPAddrLength: 128
	wire[off] = 128
	off++
	// IPv6 addr: 2001:db8::1
	copy(wire[off:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	off += 16
	// GW: 2001:db8::2
	copy(wire[off:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	off += 16
	// Label: 100 with BoS
	label := uint32(100)<<4 | 1
	wire[off] = byte(label >> 16)
	wire[off+1] = byte(label >> 8)
	wire[off+2] = byte(label)

	// Wrap: RouteType(1) + Length(1) + data
	nlriWire := make([]byte, 2+len(wire))
	nlriWire[0] = 5
	nlriWire[1] = 58
	copy(nlriWire[2:], wire)
	return nlriWire
}

func TestEvpnIPv6Address(t *testing.T) {
	prod := &producer{
		speakerHash: "test-hash",
		speakerIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}

	route, err := evpn.UnmarshalEVPNNLRI(buildEVPNType5IPv6Wire())
	if err != nil {
		t.Fatalf("UnmarshalEVPNNLRI() error: %v", err)
	}

	nlri := &evpnMockNLRI{
		route:   route,
		nextHop: "2001:db8::1",
		isIPv6:  true,
	}

	ph := &bmp.PerPeerHeader{
		PeerAS:            65001,
		PeerType:          0,
		PeerBGPID:         make([]byte, 4),
		PeerAddress:       make([]byte, 16),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}

	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
	}

	prfxs, err := prod.evpn(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("evpn() error: %v", err)
	}
	if len(prfxs) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(prfxs))
	}
	if prfxs[0].IPAddress != "2001:db8::1" {
		t.Errorf("IPAddress = %q, want '2001:db8::1'", prfxs[0].IPAddress)
	}
	if prfxs[0].GWAddress != "2001:db8::2" {
		t.Errorf("GWAddress = %q, want '2001:db8::2'", prfxs[0].GWAddress)
	}
	if prfxs[0].IPLength != 128 {
		t.Errorf("IPLength = %d, want 128", prfxs[0].IPLength)
	}
}

func buildEVPNType5IPv4Wire() []byte {
	// EVPN Type 5 IPv4: RD(8)+ESI(10)+EthTag(4)+IPLen(1)+IPv4(4)+GW(4)+Label(3) = 34
	wire := make([]byte, 34)
	off := 0
	binary.BigEndian.PutUint16(wire[off:], 0)
	off += 2
	binary.BigEndian.PutUint16(wire[off:], 0)
	off += 2
	binary.BigEndian.PutUint32(wire[off:], 100)
	off += 4
	off += 10 // ESI
	off += 4  // EthTag
	wire[off] = 24
	off++
	copy(wire[off:], []byte{10, 0, 0, 0}) // IP
	off += 4
	copy(wire[off:], []byte{10, 0, 0, 1}) // GW
	off += 4
	label := uint32(100)<<4 | 1
	wire[off] = byte(label >> 16)
	wire[off+1] = byte(label >> 8)
	wire[off+2] = byte(label)

	nlriWire := make([]byte, 2+len(wire))
	nlriWire[0] = 5
	nlriWire[1] = 34
	copy(nlriWire[2:], wire)
	return nlriWire
}

func TestEvpnIPv4Address(t *testing.T) {
	prod := &producer{
		speakerHash: "test-hash",
		speakerIP:   "10.0.0.1",
		publisher:   &mockPublisher{},
	}

	route, err := evpn.UnmarshalEVPNNLRI(buildEVPNType5IPv4Wire())
	if err != nil {
		t.Fatalf("UnmarshalEVPNNLRI() error: %v", err)
	}

	nlri := &evpnMockNLRI{
		route:   route,
		nextHop: "10.0.0.1",
		isIPv6:  false,
	}

	ph := &bmp.PerPeerHeader{
		PeerAS:            65001,
		PeerType:          0,
		PeerBGPID:         make([]byte, 4),
		PeerAddress:       make([]byte, 16),
		PeerDistinguisher: make([]byte, 8),
		PeerTimestamp:     make([]byte, 8),
	}

	update := &bgp.Update{
		BaseAttributes: &bgp.BaseAttributes{},
	}

	prfxs, err := prod.evpn(nlri, 0, ph, update)
	if err != nil {
		t.Fatalf("evpn() error: %v", err)
	}
	if len(prfxs) != 1 {
		t.Fatalf("got %d prefixes, want 1", len(prfxs))
	}
	// Verify IPv4 stays in dotted-quad form, not IPv6-mapped
	if prfxs[0].IPAddress != "10.0.0.0" {
		t.Errorf("IPAddress = %q, want '10.0.0.0'", prfxs[0].IPAddress)
	}
	if prfxs[0].GWAddress != "10.0.0.1" {
		t.Errorf("GWAddress = %q, want '10.0.0.1'", prfxs[0].GWAddress)
	}
	if prfxs[0].IPLength != 24 {
		t.Errorf("IPLength = %d, want 24", prfxs[0].IPLength)
	}
}
