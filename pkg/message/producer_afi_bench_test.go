package message

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sort"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// Each case is the wire encoding of one BGP UPDATE carried by a Route
// Monitoring message: the path attributes of a typical route plus those its
// family needs.

// Path attribute flags (RFC 4271 §4.3).
const (
	benchWellKnown   = 0x40
	benchOptional    = 0x80
	benchOptionalTra = 0xc0
)

func benchPathAttr(flags, code byte, value []byte) []byte {
	if len(value) > 255 {
		flags |= 0x10 // Extended Length
		return append(binary.BigEndian.AppendUint16([]byte{flags, code}, uint16(len(value))), value...)
	}
	return append([]byte{flags, code, byte(len(value))}, value...)
}

// benchMPReach returns MP_REACH_NLRI (RFC 4760 §3).
func benchMPReach(afi uint16, safi byte, nh, nlri []byte) []byte {
	v := append(binary.BigEndian.AppendUint16(nil, afi), safi, byte(len(nh)))
	v = append(append(v, nh...), 0x00) // Reserved
	return benchPathAttr(benchOptional, bgp.MP_REACH_NLRI, append(v, nlri...))
}

func benchRT(as uint16, n uint32) []byte {
	return binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint16([]byte{0x00, 0x02}, as), n)
}

// benchCommonAttrs returns ORIGIN, a five-AS AS_PATH, NEXT_HOP when nextHop is
// not nil, MED, LOCAL_PREF, four COMMUNITIES, two Route Targets and extComms as
// EXTENDED COMMUNITIES and two LARGE_COMMUNITY.
func benchCommonAttrs(nextHop []byte, extComms ...[]byte) [][]byte {
	asPath := []byte{0x02, 5}
	for _, as := range []uint32{65001, 3356, 1299, 2914, 13335} {
		asPath = binary.BigEndian.AppendUint32(asPath, as)
	}
	attrs := [][]byte{benchPathAttr(benchWellKnown, 1, []byte{0}), benchPathAttr(benchWellKnown, 2, asPath)}
	if nextHop != nil {
		attrs = append(attrs, benchPathAttr(benchWellKnown, 3, nextHop))
	}
	var comms, large []byte
	for _, c := range []uint32{65001<<16 | 100, 65001<<16 | 200, 3356<<16 | 2, 3356<<16 | 501} {
		comms = binary.BigEndian.AppendUint32(comms, c)
	}
	for _, c := range []uint32{65001, 1, 1, 65001, 2, 2} {
		large = binary.BigEndian.AppendUint32(large, c)
	}
	ec := append(benchRT(65001, 1), benchRT(65001, 2)...)
	for _, c := range extComms {
		ec = append(ec, c...)
	}
	return append(attrs,
		benchPathAttr(benchOptional, 4, binary.BigEndian.AppendUint32(nil, 100)),
		benchPathAttr(benchWellKnown, 5, binary.BigEndian.AppendUint32(nil, 200)),
		benchPathAttr(benchOptionalTra, 8, comms),
		benchPathAttr(benchOptionalTra, 16, ec),
		benchPathAttr(benchOptionalTra, 32, large),
	)
}

// benchUpdate returns the body of an UPDATE with the path attributes sorted by
// type code and the NLRI field nlri.
func benchUpdate(attrs [][]byte, nlri []byte) []byte {
	sort.SliceStable(attrs, func(i, j int) bool { return attrs[i][1] < attrs[j][1] })
	var pa []byte
	for _, a := range attrs {
		pa = append(pa, a...)
	}
	b := append([]byte{0, 0}, binary.BigEndian.AppendUint16(nil, uint16(len(pa)))...)
	return append(append(b, pa...), nlri...)
}

// benchPeerHeader returns the Peer header of the IPv4 peer 192.0.2.1, AS 65000,
// with a peer timestamp as a router sets it.
func benchPeerHeader() *bmp.PerPeerHeader {
	b := []byte{byte(bmp.PeerType0), 0}
	b = append(b, make([]byte, 20)...) // Peer Distinguisher, IPv6 part of the address
	b = append(b, 192, 0, 2, 1, 0x00, 0x00, 0xfd, 0xe8)
	b = append(b, net.ParseIP("10.0.0.1").To4()...)
	b = append(b, 0x68, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00)
	ph, err := bmp.UnmarshalPerPeerHeader(b)
	if err != nil {
		panic(err)
	}
	return attachDefaultTestIdentity(ph)
}

func benchPeerUp(ph *bmp.PerPeerHeader) bmp.Message {
	local := make([]byte, 16)
	copy(local[10:], []byte{0xff, 0xff, 192, 168, 1, 1})
	return bmp.Message{
		PeerHeader: ph,
		Payload: &bmp.PeerUpMessage{
			LocalAddress: local, LocalPort: 179, RemotePort: 45678,
			SentOpen:     &bgp.OpenMessage{Version: 4, MyAS: 65000, HoldTime: 90, BGPID: []byte{10, 0, 0, 1}},
			ReceivedOpen: &bgp.OpenMessage{Version: 4, MyAS: 65001, HoldTime: 90, BGPID: []byte{10, 0, 0, 2}},
		},
		SpeakerIP: "10.2.1.3",
	}
}

type discardPublisher struct{}

func (discardPublisher) PublishMessage(int, []byte, []byte) error { return nil }
func (discardPublisher) Stop()                                    {}

// benchRepeat concatenates nlri(i) for i in [0, n).
func benchRepeat(n int, nlri func(i int) []byte) []byte {
	var b []byte
	for i := 0; i < n; i++ {
		b = append(b, nlri(i)...)
	}
	return b
}

var (
	benchV4NH   = []byte{192, 0, 2, 1}
	benchV6NH   = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	benchRD     = []byte{0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01} // 65001:1
	benchVPNNH4 = append(make([]byte, 8), benchV4NH...)                  // RD 0 + IPv4
	benchVPNNH6 = append(make([]byte, 8), benchV6NH...)                  // RD 0 + IPv6
)

// benchV4Prefix returns 10.(i/256).(i%256).0/24.
func benchV4Prefix(i int) []byte { return []byte{24, 10, byte(i >> 8), byte(i)} }

// benchLUPrefix returns 10.255.(i/256).(i%256)/32 with label 16000+i.
func benchLUPrefix(i int) []byte {
	v := (16000+uint32(i))<<4 | 1
	return []byte{24 + 32, byte(v >> 16), byte(v >> 8), byte(v), 10, 255, byte(i >> 8), byte(i)}
}

// benchVPNPrefix returns 10.(i/256).(i%256).0/24 under label and RD 65001:1.
func benchVPNPrefix(label []byte) func(int) []byte {
	return func(i int) []byte {
		b := append([]byte{24 + 24 + 64}, label...)
		return append(append(b, benchRD...), 10, byte(i>>8), byte(i))
	}
}

// benchSRv6L3Service returns an SRv6 L3 Service TLV (RFC 9252 §2) of SID
// 2001:db8:1:1:: with behavior End.DT4 and a SID Structure.
func benchSRv6L3Service() []byte {
	info := []byte{0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 19, 0x00}
	info = append(info, 0x01, 0x00, 0x06, 40, 24, 16, 0, 16, 64)
	v := append([]byte{0x00, 0x01, 0x00, byte(len(info))}, info...)
	return append([]byte{0x05, 0x00, byte(len(v))}, v...)
}

// benchEVPNType2 returns a MAC/IP Advertisement route (RFC 7432 §7.2) for MAC
// 00:00:5e:00:(i/256):(i%256) and IPv4 10.10.(i/256).(i%256), VNI 10100.
func benchEVPNType2(i int) []byte {
	v := append([]byte(nil), benchRD...)
	v = append(v, make([]byte, 14)...) // ESI 0, Ethernet Tag ID 0
	v = append(v, 48, 0x00, 0x00, 0x5e, 0x00, byte(i>>8), byte(i))
	v = append(v, 32, 10, 10, byte(i>>8), byte(i), 0x00, 0x27, 0x74)
	return append([]byte{2, byte(len(v))}, v...)
}

func benchTLV(t uint16, v ...byte) []byte {
	return append(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, t), uint16(len(v))), v...)
}

// benchLSPrefix returns an IPv4 Topology Prefix NLRI (RFC 9552 §5.2.3) of IS-IS
// Level 2 with a Local Node Descriptor of AS 65001, BGP-LS ID 0 and IS-IS
// System ID 0000.0000.0001.
func benchLSPrefix(i int) []byte {
	node := benchTLV(256, append(append(benchTLV(512, 0, 0, 0xfd, 0xe9),
		benchTLV(513, 0, 0, 0, 0)...), benchTLV(515, 0, 0, 0, 0, 0, 1)...)...)
	v := append([]byte{2, 0, 0, 0, 0, 0, 0, 0, 0}, node...)
	return benchTLV(3, append(v, benchTLV(265, 24, 10, 40, byte(i))...)...)
}

// benchLSPrefixAttr is a BGP-LS Attribute with IGP flags, metric and a Prefix
// SID.
var benchLSPrefixAttr = benchPathAttr(benchOptional, 29, append(append(
	benchTLV(1152, 0x00), benchTLV(1155, 0, 0, 0, 10)...),
	benchTLV(1158, 0x40, 0, 0, 0, 0, 0, 0, 0x65)...))

// benchSRPolicyTunnelEncap is a Tunnel Encapsulation Attribute (RFC 9012) with
// an SR Policy tunnel: Preference, Binding SID and two segment lists.
var benchSRPolicyTunnelEncap = benchPathAttr(benchOptionalTra, 23, []byte{
	0x00, 0x0F, 0x00, 0x48, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0D, 0x06, 0x00, 0x00,
	0xDB, 0xBA, 0x00, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x00,
	0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00,
	0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0xD0, 0x00,
})

// benchFlowspec returns a Flow Specification (RFC 8955 §4) of destination
// 10.30.i.0/24, TCP, destination port 443.
func benchFlowspec(i int) []byte {
	v := []byte{0x01, 24, 10, 30, byte(i), 0x03, 0x81, 0x06, 0x05, 0x91, 0x01, 0xbb}
	return append([]byte{byte(len(v))}, v...)
}

// benchMUPISD returns an Interwork Segment Discovery route for 10.50.i.0/24.
func benchMUPISD(i int) []byte {
	v := append(append([]byte(nil), benchRD...), 24, 10, 50, byte(i))
	return append([]byte{0x01, 0x00, 0x01, byte(len(v))}, v...)
}

type afiBenchCase struct {
	name    string
	routes  int // NLRI of the UPDATE, and messages it must produce
	msgType int
	update  []byte
}

func afiBenchCases() []afiBenchCase {
	var cases []afiBenchCase
	add := func(name string, routes, msgType int, update []byte) {
		cases = append(cases, afiBenchCase{fmt.Sprintf("%s/nlri=%d", name, routes), routes, msgType, update})
	}
	withAttrs := func(extra ...[]byte) [][]byte { return append(benchCommonAttrs(nil), extra...) }
	for _, n := range []int{1, 64} {
		add("ipv4-unicast-mp-reach", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(withAttrs(benchMPReach(1, 1, benchV4NH, benchRepeat(n, benchV4Prefix))), nil))
		add("ipv4-labeled-unicast-prefix-sid", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(withAttrs(benchMPReach(1, 4, benchV4NH, benchRepeat(n, benchLUPrefix)),
				// Label Index 100, Originator SRGB 16000+8000 (RFC 8669 §3).
				benchPathAttr(benchOptionalTra, 40, []byte{
					0x01, 0x00, 0x07, 0, 0, 0, 0, 0, 0, 0x64,
					0x03, 0x00, 0x08, 0, 0, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40})), nil))
		add("vpnv4", n, bmp.L3VPNV4Msg,
			benchUpdate(withAttrs(benchMPReach(1, 128, benchVPNNH4, benchRepeat(n, benchVPNPrefix([]byte{0x05, 0xdc, 0x11})))), nil))
		add("vpnv4-srv6", n, bmp.L3VPNV4Msg,
			benchUpdate(withAttrs(benchMPReach(1, 128, benchVPNNH6, benchRepeat(n, benchVPNPrefix([]byte{0x00, 0x40, 0x00}))),
				benchPathAttr(benchOptionalTra, 40, benchSRv6L3Service())), nil))
		add("evpn-type2-mac-ip", n, bmp.EVPNMsg,
			benchUpdate(append(benchCommonAttrs(nil, []byte{0x03, 0x0c, 0, 0, 0, 0, 0x00, 0x08}), // VXLAN
				benchMPReach(25, 70, benchV4NH, benchRepeat(n, benchEVPNType2))), nil))
		add("bgp-ls-prefix", n, bmp.LSPrefixMsg,
			benchUpdate(append(benchCommonAttrs(nil)[:2],
				benchMPReach(16388, 71, benchV4NH, benchRepeat(n, benchLSPrefix)), benchLSPrefixAttr), nil))
		add("flowspec-v4", n, bmp.FlowspecV4Msg,
			benchUpdate(append(benchCommonAttrs(nil, []byte{0x80, 0x06, 0, 0, 0, 0, 0, 0}), // traffic-rate 0
				benchMPReach(1, 133, nil, benchRepeat(n, benchFlowspec))), nil))
		add("mup-isd", n, bmp.MUPV4Msg,
			benchUpdate(withAttrs(benchMPReach(1, 85, benchV4NH, benchRepeat(n, benchMUPISD)),
				benchPathAttr(benchOptionalTra, 40, mupPrefixSIDAttribute())), nil))
	}
	// An SR Policy candidate path has its own Tunnel Encapsulation, so one NLRI
	// per UPDATE.
	add("sr-policy-v4", 1, bmp.SRPolicyV4Msg,
		benchUpdate(withAttrs(
			benchMPReach(1, 73, benchV4NH, []byte{96, 0, 0, 0, 1, 0, 0, 0, 100, 10, 0, 0, 9}), // Color 100, Endpoint 10.0.0.9
			benchSRPolicyTunnelEncap), nil))
	return cases
}

// routeMonitor returns the Route Monitoring message of c.
func routeMonitor(tb testing.TB, ph *bmp.PerPeerHeader, c afiBenchCase) bmp.Message {
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(c.update, true)
	if err != nil {
		tb.Fatalf("%s: %v", c.name, err)
	}
	return bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}, SpeakerIP: "10.2.1.3"}
}

// TestAFIBenchCases checks every case publishes c.routes messages of c.msgType,
// so a decode failure, which is only logged, does not go unnoticed.
func TestAFIBenchCases(t *testing.T) {
	for _, c := range afiBenchCases() {
		ph := benchPeerHeader()
		pub := &recordingPublisher{}
		p := NewProducer(pub, true).(*producer)
		p.producingWorker(benchPeerUp(ph))
		n := len(pub.msgs)
		p.producingWorker(routeMonitor(t, ph, c))
		if len(pub.msgs)-n != c.routes {
			t.Fatalf("%s: published %d messages, want %d", c.name, len(pub.msgs)-n, c.routes)
		}
		for _, m := range pub.msgs[n:] {
			if m.msgType != c.msgType {
				t.Fatalf("%s: message type %d, want %d: %s", c.name, m.msgType, c.msgType, m.payload)
			}
		}
	}
}

// BenchmarkProducerAFI feeds b.N Route Monitoring messages of each case through
// the producer, after a Peer Up, and reports time, bytes and allocations per
// route.
func BenchmarkProducerAFI(b *testing.B) {
	for _, c := range afiBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			ph := benchPeerHeader()
			p := NewProducer(discardPublisher{}, true).(*producer)
			p.producingWorker(benchPeerUp(ph))
			rm := routeMonitor(b, ph, c)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.producingWorker(rm)
			}
			b.StopTimer()
			runtime.ReadMemStats(&after)
			routes := float64(b.N) * float64(c.routes)
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/routes, "ns/route")
			b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/routes, "B/route")
			b.ReportMetric(float64(after.Mallocs-before.Mallocs)/routes, "allocs/route")
		})
	}
}
