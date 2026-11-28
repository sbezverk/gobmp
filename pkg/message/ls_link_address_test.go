package message

import (
	"cmp"
	"encoding/json"
	"slices"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestPublishedLSLinkAddresses(t *testing.T) {
	localNode := benchTLV(256, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe8),
		benchTLV(515, 0, 0, 0, 0, 0, 1),
	)...)
	remoteNode := benchTLV(257, slices.Concat(
		benchTLV(512, 0, 0, 0xfd, 0xe8),
		benchTLV(515, 0, 0, 0, 0, 0, 2),
	)...)
	localIPv4 := benchTLV(259, 198, 51, 100, 1)
	remoteIPv4 := benchTLV(260, 198, 51, 100, 2)
	localIPv6 := benchTLV(261, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	remoteIPv6 := benchTLV(262, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)

	// An empty value means the JSON key must be absent.
	type addresses struct {
		localIP, remoteIP, localIPv4, remoteIPv4, localIPv6, remoteIPv6 string
	}
	dualStack := addresses{
		localIP: "198.51.100.1", remoteIP: "198.51.100.2",
		localIPv4: "198.51.100.1", remoteIPv4: "198.51.100.2",
		localIPv6: "2001:db8::1", remoteIPv6: "2001:db8::2",
	}
	// RFC 9815 Sections 5.2.2 and 5.2.4: an SPF link needs an IGP Metric (1095)
	// and a Sequence Number (1181), else it is published as a withdrawal.
	spfAttribute := benchPathAttr(benchOptional, 29, slices.Concat(
		benchTLV(1095, 0, 0, 0, 10),
		benchTLV(1181, 0, 0, 0, 0, 0, 0, 0, 1),
	))
	tests := []struct {
		name        string
		safi        byte // zero means 71 (BGP-LS)
		descriptors [][]byte
		attribute   []byte
		withdraw    bool
		want        addresses
		wantRD      string
	}{
		{
			name:        "publishes only IPv4 keys for IPv4 descriptors",
			descriptors: [][]byte{localIPv4, remoteIPv4},
			want: addresses{
				localIP: "198.51.100.1", remoteIP: "198.51.100.2",
				localIPv4: "198.51.100.1", remoteIPv4: "198.51.100.2",
			},
		},
		{
			name:        "publishes IPv6 in the preferred and IPv6 keys for IPv6 descriptors",
			descriptors: [][]byte{localIPv6, remoteIPv6},
			want: addresses{
				localIP: "2001:db8::1", remoteIP: "2001:db8::2",
				localIPv6: "2001:db8::1", remoteIPv6: "2001:db8::2",
			},
		},
		{
			name:        "keeps both families and prefers IPv4 for a dual-stack link",
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			want:        dualStack,
		},
		{
			name:        "keeps both families when a dual-stack link is withdrawn",
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			withdraw:    true,
			want:        dualStack,
		},
		{
			name:        "keeps each endpoint independent when the families are mixed",
			descriptors: [][]byte{localIPv4, remoteIPv6},
			want: addresses{
				localIP: "198.51.100.1", remoteIP: "2001:db8::2",
				localIPv4: "198.51.100.1", remoteIPv6: "2001:db8::2",
			},
		},
		{
			name: "omits all address keys when there are no address descriptors",
		},
		{
			name:        "publishes the RD and both families for a BGP-LS-VPN link",
			safi:        72,
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			want:        dualStack,
			wantRD:      "65000:1",
		},
		{
			name:        "keeps the RD and both families when a BGP-LS-VPN link is withdrawn",
			safi:        72,
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			withdraw:    true,
			want:        dualStack,
			wantRD:      "65000:1",
		},
		{
			name:        "publishes both families for a BGP-LS-SPF link",
			safi:        80,
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			attribute:   spfAttribute,
			want:        dualStack,
		},
		{
			name:        "keeps both families when a BGP-LS-SPF link is withdrawn",
			safi:        80,
			descriptors: [][]byte{localIPv4, remoteIPv4, localIPv6, remoteIPv6},
			withdraw:    true,
			want:        dualStack,
		},
		// The legacy local_link_ip/remote_link_ip values in the next two cases
		// record current behavior, not behavior an RFC requires.
		{
			name:        "omits the IPv6 key for a 4-octet value in an IPv6 descriptor",
			descriptors: [][]byte{benchTLV(261, 198, 51, 100, 1)},
			want:        addresses{localIP: "198.51.100.1"},
		},
		{
			name: "omits the IPv4 key for a 16-octet value in an IPv4 descriptor",
			descriptors: [][]byte{
				benchTLV(259, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 1),
			},
			want: addresses{localIP: "198.51.100.1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			safi := cmp.Or(tc.safi, 71)
			protocol := base.ISISL2
			if safi == 80 {
				protocol = base.Direct // RFC 9815 Section 5.2
			}
			nlri := lsUnknownTLVTestNLRI(2, protocol, slices.Concat([][]byte{localNode, remoteNode}, tc.descriptors)...)
			nextHop := []byte{203, 0, 113, 1}
			if safi == 72 {
				// RFC 9552 Section 5.2: an RD precedes the NLRI body and the next hop.
				nlri = testLSVPNEntry(2, testRD, nlri[4:])
				nextHop = append(make([]byte, 8), nextHop...)
			}
			mpAttr := benchMPReach(16388, safi, nextHop, nlri)
			wantAction := "add"
			if tc.withdraw {
				mpAttr = benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI, append([]byte{0x40, 0x04, safi}, nlri...))
				wantAction = "del"
			}
			attrs := [][]byte{mpAttr}
			if tc.attribute != nil {
				attrs = append(attrs, tc.attribute)
			}
			update, err := bgp.UnmarshalBGPUpdate(benchUpdate(attrs, nil))
			if err != nil {
				t.Fatalf("unmarshal BGP UPDATE: %v", err)
			}
			peerHeader := makePeerHeader(t, bmp.PeerType0, 0)
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}

			p.produceRouteMessage(bmp.Message{PeerHeader: peerHeader, Payload: &bmp.RouteMonitor{Update: update}})

			if len(publisher.msgs) != 1 {
				t.Fatalf("published %d events, want 1", len(publisher.msgs))
			}
			got := publisher.msgs[0]
			if got.msgType != bmp.LSLinkMsg {
				t.Fatalf("message type = %d, want %d", got.msgType, bmp.LSLinkMsg)
			}
			// The broker key stays the router hash and ls_link carries no route hash.
			if string(got.key) != peerHeader.Identity.RouterHash || len(got.key) == 0 {
				t.Errorf("broker key = %q, want router hash %q", got.key, peerHeader.Identity.RouterHash)
			}
			var payload map[string]any
			if err := json.Unmarshal(got.payload, &payload); err != nil {
				t.Fatalf("unmarshal published event: %v", err)
			}
			for key, want := range map[string]string{
				"action":              wantAction,
				"hash":                "",
				"route_distinguisher": tc.wantRD,
				"local_link_ip":       tc.want.localIP,
				"remote_link_ip":      tc.want.remoteIP,
				"local_link_ipv4":     tc.want.localIPv4,
				"remote_link_ipv4":    tc.want.remoteIPv4,
				"local_link_ipv6":     tc.want.localIPv6,
				"remote_link_ipv6":    tc.want.remoteIPv6,
			} {
				value, present := payload[key]
				if want == "" {
					if present {
						t.Errorf("%s = %v, want the key omitted", key, value)
					}
					continue
				}
				if value != want {
					t.Errorf("%s = %v, want %q", key, value, want)
				}
			}
		})
	}
}
