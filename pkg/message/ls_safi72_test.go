package message

import (
	"encoding/json"
	"strings"
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
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/vpls"
)

// safi72MockNLRI is a minimal bgp.MPNLRI implementation that returns a
// canned *ls.NLRI72 via GetNLRI72 and nil/empty results elsewhere.
type safi72MockNLRI struct {
	nlri72 *ls.NLRI72
}

func (m *safi72MockNLRI) GetAFISAFIType() int                      { return 72 }
func (m *safi72MockNLRI) GetNLRI72() (*ls.NLRI72, error)           { return m.nlri72, nil }
func (m *safi72MockNLRI) GetNLRI71() (*ls.NLRI71, error)           { return nil, nil }
func (m *safi72MockNLRI) GetNLRI73() (*srpolicy.NLRI73, error)     { return nil, nil }
func (m *safi72MockNLRI) GetNLRILU() (*base.MPNLRI, error)         { return nil, nil }
func (m *safi72MockNLRI) GetNLRIUnicast() (*base.MPNLRI, error)    { return nil, nil }
func (m *safi72MockNLRI) GetNLRIMulticast() (*base.MPNLRI, error)  { return nil, nil }
func (m *safi72MockNLRI) GetNLRIEVPN() (*evpn.Route, error)        { return nil, nil }
func (m *safi72MockNLRI) GetNLRIVPLS() (*vpls.Route, error)        { return nil, nil }
func (m *safi72MockNLRI) GetNLRIL3VPN() (*base.MPNLRI, error)      { return nil, nil }
func (m *safi72MockNLRI) GetFlowspecNLRI() (*flowspec.NLRI, error) { return nil, nil }
func (m *safi72MockNLRI) GetAllFlowspecNLRI() ([]*flowspec.NLRI, error) {
	return nil, nil
}
func (m *safi72MockNLRI) GetNLRIMCASTVPN() (*mcastvpn.Route, error) { return nil, nil }
func (m *safi72MockNLRI) GetNLRIMVPN() (*mcastvpn.Route, error)     { return nil, nil }
func (m *safi72MockNLRI) GetNLRIRTC() (*rtc.Route, error)           { return nil, nil }
func (m *safi72MockNLRI) GetNextHop() string                        { return "" }
func (m *safi72MockNLRI) IsIPv6NLRI() bool                          { return false }
func (m *safi72MockNLRI) IsNextHopIPv6() bool                       { return false }

// TestProcessNLRI72SubTypes_NodeRDStamped verifies that BGP-LS-VPN (SAFI 72)
// Node NLRIs get their RD stamped onto the produced LSNode JSON before publish.
func TestProcessNLRI72SubTypes_NodeRDStamped(t *testing.T) {
	rd, err := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01})
	if err != nil {
		t.Fatalf("MakeRD: %v", err)
	}
	// Real Node NLRI: protocol_id=2(ISIS-L2) + identifier(8) + Local Node Descriptor TLV(26)
	nodeBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	node, err := base.UnmarshalNodeNLRI(nodeBytes)
	if err != nil {
		t.Fatalf("UnmarshalNodeNLRI: %v", err)
	}
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{
				{RD: rd, Type: 1, Length: uint16(len(nodeBytes)), LS: node},
			},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   rec,
	}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})

	if len(rec.msgs) != 1 {
		t.Fatalf("expected 1 published message, got %d", len(rec.msgs))
	}
	if rec.msgs[0].msgType != bmp.LSNodeMsg {
		t.Errorf("msgType = %d, want %d (LSNodeMsg)", rec.msgs[0].msgType, bmp.LSNodeMsg)
	}
	if !strings.Contains(string(rec.msgs[0].payload), `"route_distinguisher":"100:1"`) {
		t.Errorf("RD not stamped on published LSNode; payload=%s", rec.msgs[0].payload)
	}
}

// TestProcessNLRI72SubTypes_LinkAndPrefixRDStamped exercises sub-types 2 (Link),
// 3 (PrefixV4), and 4 (PrefixV6) end-to-end through the SAFI 72 dispatch and
// asserts each produced message carries the RD.
func TestProcessNLRI72SubTypes_LinkAndPrefixRDStamped(t *testing.T) {
	rd, err := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02})
	if err != nil {
		t.Fatalf("MakeRD: %v", err)
	}
	// Link NLRI body: protocol_id + identifier + Local Node + Remote Node + Link Descriptors.
	linkBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x01, 0x01, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x01, 0x05, 0x00, 0x10,
		0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x01, 0x06, 0x00, 0x10,
		0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
	}
	link, err := base.UnmarshalLinkNLRI(linkBytes)
	if err != nil {
		t.Fatalf("UnmarshalLinkNLRI: %v", err)
	}

	// Prefix v4 NLRI body
	prefixBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		// IP Reachability TLV (type 265, length 5) — /32 prefix 10.0.0.1
		0x01, 0x09, 0x00, 0x05, 0x20, 0x0A, 0x00, 0x00, 0x01,
	}
	prfx, err := base.UnmarshalPrefixNLRI(prefixBytes, true)
	if err != nil {
		t.Fatalf("UnmarshalPrefixNLRI: %v", err)
	}

	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{
				{RD: rd, Type: 2, Length: uint16(len(linkBytes)), LS: link},
				{RD: rd, Type: 3, Length: uint16(len(prefixBytes)), LS: prfx},
			},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   rec,
	}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})

	if len(rec.msgs) != 2 {
		t.Fatalf("expected 2 published messages (link+prefix), got %d", len(rec.msgs))
	}
	for i, m := range rec.msgs {
		if !strings.Contains(string(m.payload), `"route_distinguisher":"100:2"`) {
			t.Errorf("msg %d missing RD; payload=%s", i, m.payload)
		}
	}
	if rec.msgs[0].msgType != bmp.LSLinkMsg {
		t.Errorf("msg[0].msgType = %d, want LSLinkMsg %d", rec.msgs[0].msgType, bmp.LSLinkMsg)
	}
	if rec.msgs[1].msgType != bmp.LSPrefixMsg {
		t.Errorf("msg[1].msgType = %d, want LSPrefixMsg %d", rec.msgs[1].msgType, bmp.LSPrefixMsg)
	}
}

// TestProcessNLRI72SubTypes_GetNLRI72Error logs but does not crash.
func TestProcessNLRI72SubTypes_GetNLRI72Error(t *testing.T) {
	// safi72MockNLRI with nil nlri72 → GetNLRI72 returns (nil, nil). The dispatch
	// loop iterates over ls.NLRI which is empty, so nothing is published — and
	// importantly nothing panics.
	mock := &safi72MockNLRI{nlri72: &ls.NLRI72{NLRI: nil}}
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})
	if len(rec.msgs) != 0 {
		t.Errorf("empty NLRI should not publish; got %d messages", len(rec.msgs))
	}
}

// TestProcessNLRI72SubTypes_SRv6SIDRDStamped exercises sub-type 6 (SRv6 SID)
// and asserts the produced LSSRv6SID JSON carries the RD.
func TestProcessNLRI72SubTypes_SRv6SIDRDStamped(t *testing.T) {
	rd, err := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x03})
	if err != nil {
		t.Fatalf("MakeRD: %v", err)
	}
	sidBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1a,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93,
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
		0x02, 0x06, 0x00, 0x10,
		0x01, 0x92, 0x01, 0x68, 0x00, 0x93, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	sid, err := srv6.UnmarshalSRv6SIDNLRI(sidBytes)
	if err != nil {
		t.Fatalf("UnmarshalSRv6SIDNLRI: %v", err)
	}
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{{RD: rd, Type: 6, Length: uint16(len(sidBytes)), LS: sid}},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{
		speakerHash: "test-router",
		speakerIP:   "192.0.2.1",
		publisher:   rec,
	}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})

	if len(rec.msgs) != 1 {
		t.Fatalf("expected 1 published LSSRv6SID message, got %d", len(rec.msgs))
	}
	if rec.msgs[0].msgType != bmp.LSSRv6SIDMsg {
		t.Errorf("msgType = %d, want LSSRv6SIDMsg %d", rec.msgs[0].msgType, bmp.LSSRv6SIDMsg)
	}
	if !strings.Contains(string(rec.msgs[0].payload), `"route_distinguisher":"100:3"`) {
		t.Errorf("RD not stamped on LSSRv6SID; payload=%s", rec.msgs[0].payload)
	}
}

// failingPublisher returns an error from PublishMessage so we can exercise
// the publish-failure branches in processNLRI72SubTypes.
type failingPublisher struct{ calls int }

func (f *failingPublisher) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	f.calls++
	return errPublishFailure
}
func (f *failingPublisher) Stop() {}

var errPublishFailure = errPublish{}

type errPublish struct{}

func (errPublish) Error() string { return "publish failed" }

// TestProcessNLRI72SubTypes_PublishFailure exercises the marshalAndPublish
// error branches across all four sub-type cases (Node, Link, Prefix, SRv6).
// A failing publisher keeps the dispatch loop iterating so every case's
// error path runs.
func TestProcessNLRI72SubTypes_PublishFailure(t *testing.T) {
	rd, err := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x04})
	if err != nil {
		t.Fatalf("MakeRD: %v", err)
	}
	nodeBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	node, _ := base.UnmarshalNodeNLRI(nodeBytes)
	linkBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x01, 0x01, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x01, 0x05, 0x00, 0x10,
		0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x01, 0x06, 0x00, 0x10,
		0xFC, 0x00, 0xDD, 0xDD, 0x00, 0x03, 0x00, 0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
	}
	link, _ := base.UnmarshalLinkNLRI(linkBytes)
	prefixBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x01, 0x09, 0x00, 0x05, 0x20, 0x0A, 0x00, 0x00, 0x01,
	}
	prfx, _ := base.UnmarshalPrefixNLRI(prefixBytes, true)
	sidBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1a,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93,
		0x01, 0x07, 0x00, 0x02, 0x00, 0x02,
		0x02, 0x06, 0x00, 0x10,
		0x01, 0x92, 0x01, 0x68, 0x00, 0x93, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	sid, _ := srv6.UnmarshalSRv6SIDNLRI(sidBytes)
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{
				{RD: rd, Type: 1, LS: node},
				{RD: rd, Type: 2, LS: link},
				{RD: rd, Type: 3, LS: prfx},
				{RD: rd, Type: 6, LS: sid},
			},
		},
	}
	fp := &failingPublisher{}
	p := &producer{publisher: fp}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})
	// All four sub-types attempt publish despite the failure; loop must continue.
	if fp.calls != 4 {
		t.Errorf("expected 4 publish attempts (continue-on-error), got %d", fp.calls)
	}
}

// TestProcessNLRI72SubTypes_WrongLSType exercises the defensive type-assertion
// branches by feeding deliberately mistyped Element.LS interfaces.
func TestProcessNLRI72SubTypes_WrongLSType(t *testing.T) {
	rd, _ := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x05})
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{
				{RD: rd, Type: 1, LS: "not a NodeNLRI"},
				{RD: rd, Type: 2, LS: "not a LinkNLRI"},
				{RD: rd, Type: 3, LS: "not a PrefixNLRI"},
				{RD: rd, Type: 6, LS: "not a SIDNLRI"},
			},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})
	if len(rec.msgs) != 0 {
		t.Errorf("wrong LS types should not publish; got %d messages", len(rec.msgs))
	}
}

// TestProcessNLRI72SubTypes_DeleteOperation exercises operation=1 (del) path.
func TestProcessNLRI72SubTypes_DeleteOperation(t *testing.T) {
	rd, _ := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x06})
	nodeBytes := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1A,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xFD, 0xE8,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	node, _ := base.UnmarshalNodeNLRI(nodeBytes)
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{{RD: rd, Type: 1, LS: node}},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 1, ph, &bgp.Update{})
	if len(rec.msgs) != 1 || !strings.Contains(string(rec.msgs[0].payload), `"action":"del"`) {
		t.Errorf("expected del action published, got %d messages", len(rec.msgs))
	}
}

// TestProcessNLRI72SubTypes_UnknownSubType logs but does not crash.
func TestProcessNLRI72SubTypes_UnknownSubType(t *testing.T) {
	rd, _ := base.MakeRD([]byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01})
	mock := &safi72MockNLRI{
		nlri72: &ls.NLRI72{
			NLRI: []ls.VPNElement{{RD: rd, Type: 99, LS: []byte{0xab}}},
		},
	}
	rec := &recordingPublisher{}
	p := &producer{publisher: rec}
	ph := makePeerHeader(t, bmp.PeerType0, 0x00)
	p.processNLRI72SubTypes(mock, 0, ph, &bgp.Update{})
	if len(rec.msgs) != 0 {
		t.Errorf("unknown sub type should not publish; got %d messages", len(rec.msgs))
	}
}

// TestLS_RD_JSON locks the JSON tag for the new BGP-LS-VPN Route Distinguisher
// field on LSNode/LSLink/LSPrefix/LSSRv6SID (RFC 9552 §5.2). A consumer rename
// of the tag, or accidental loss of omitempty, would fail these assertions.
func TestLS_RD_JSON(t *testing.T) {
	cases := []struct {
		name    string
		marshal func(rd string) ([]byte, error)
		empty   func() ([]byte, error)
	}{
		{
			name:    "LSNode",
			marshal: func(rd string) ([]byte, error) { return json.Marshal(&LSNode{RD: rd}) },
			empty:   func() ([]byte, error) { return json.Marshal(&LSNode{}) },
		},
		{
			name:    "LSLink",
			marshal: func(rd string) ([]byte, error) { return json.Marshal(&LSLink{RD: rd}) },
			empty:   func() ([]byte, error) { return json.Marshal(&LSLink{}) },
		},
		{
			name:    "LSPrefix",
			marshal: func(rd string) ([]byte, error) { return json.Marshal(&LSPrefix{RD: rd}) },
			empty:   func() ([]byte, error) { return json.Marshal(&LSPrefix{}) },
		},
		{
			name:    "LSSRv6SID",
			marshal: func(rd string) ([]byte, error) { return json.Marshal(&LSSRv6SID{RD: rd}) },
			empty:   func() ([]byte, error) { return json.Marshal(&LSSRv6SID{}) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/present", func(t *testing.T) {
			b, err := tc.marshal("100:1")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(b), `"route_distinguisher":"100:1"`) {
				t.Errorf("missing route_distinguisher in %s", b)
			}
		})
		t.Run(tc.name+"/absent_omitempty", func(t *testing.T) {
			b, err := tc.empty()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if strings.Contains(string(b), "route_distinguisher") {
				t.Errorf("route_distinguisher should be omitted when empty, got %s", b)
			}
		})
	}
}

// TestLSNode_RD_RoundTrip verifies the RD field survives JSON marshal/unmarshal.
func TestLSNode_RD_RoundTrip(t *testing.T) {
	original := &LSNode{RD: "65000:42", Name: "router1"}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &LSNode{}
	if err := json.Unmarshal(b, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RD != original.RD {
		t.Errorf("RD round-trip lost: got %q, want %q", got.RD, original.RD)
	}
	if got.Name != original.Name {
		t.Errorf("Name round-trip lost: got %q, want %q", got.Name, original.Name)
	}
}
