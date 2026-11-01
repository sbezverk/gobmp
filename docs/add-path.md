# ADD-PATH negotiation and peer isolation

goBMP selects the NLRI wire format from the OPEN capabilities associated with
each monitored peer. A wrong selection can interpret the four-byte Path
Identifier as prefix data even when the resulting prefixes pass basic parsing.
For example, PathID 256 followed by `192.0.2.0/24` can become four routes with
lost path identity when decoded without ADD-PATH.

## Direction and exact address family

`OpenMessage.AddPathModes()` exposes the advertised mode for each exact
`bgp.AFISAFI` pair: receive (1), send (2), or both (3). Invalid modes and malformed
capability tuples are ignored. The existing `AddPathCapability()` signature and
behavior remain available for callers that already use that API.

For ordinary peers, the collector applies the following negotiation:

| Monitored view | Local OPEN | Remote OPEN |
| --- | --- | --- |
| Adj-RIB-In | Can receive | Can send |
| Adj-RIB-Out | Can send | Can receive |

This accepts complementary modes 1/2 as well as bidirectional mode 3. The O flag
selects the view after session lookup; O/L/A flags do not create separate
session identities. PeerDown removes both negotiated directions. These rules
follow [RFC 7911 sections 4–5](https://www.rfc-editor.org/rfc/rfc7911.html#section-4)
and [RFC 8671 sections 4 and 6.3](https://www.rfc-editor.org/rfc/rfc8671.html#section-4).

Negotiation uses exact AFI/SAFI keys. The adapter to existing MP parser maps
translates only the current attribute's family, so output message types shared
by IPv4, IPv6, and VPN FlowSpec cannot mix their capability state.

## Message lifecycle

Each BMP connection processes PeerUp, routes, statistics, and PeerDown in input
order. PeerUp installs negotiated ADD-PATH and table properties before marking
the speaker ready. A route completes its local `PublishMessage` calls before a
later PeerDown or replacement PeerUp can remove or replace those properties.
This includes updates containing both MP_REACH and MP_UNREACH attributes.
Parsed route/statistics messages received before the first valid PeerUp use a
[bounded compatibility buffer](message-ordering.md#traffic-before-peer-up).
Replay requires the message's own installed peer state. Loc-RIB routes also
require every legacy or MP AFI/SAFI in the UPDATE to be explicitly described;
membership includes families described without ADD-PATH. Missing or
indeterminate state discards the entire buffered message with a diagnostic,
even if a later PeerUp would describe it. Matching-peer replay keeps its
negotiated direction and PathIDs. Separate connections retain separate
producers and can progress independently. This policy does not guarantee
lossless replay or alter live traffic after the first valid PeerUp.

The ordering covers local publication calls; it does not establish delivery or
commit order across broker topics. An active publisher call has no cancellation
API and can hold up its connection's producer. Server shutdown retains the
[per-connection drain and join policy](message-ordering.md): accepted frames
finish their local publication calls before the publisher stops. A blocked
publisher call can therefore delay server shutdown too.

## Loc-RIB and internal keys

Loc-RIB OPENs are fabricated descriptions of the exported table. Under
[RFC 9069 section 5.2](https://www.rfc-editor.org/rfc/rfc9069.html#section-5.2),
the presence of a valid ADD-PATH tuple enables PathIDs for that family regardless
of its send/receive mode. Separate PeerUp messages may describe different
families of one Loc-RIB. Each updates its explicitly declared MP/ADD-PATH
families: a repeated MP family without ADD-PATH clears the previous setting,
while other families retain their settings.

Peer capability and identity caches use the raw Peer Distinguisher bytes.
Loc-RIB table-name lookup also uses the complete distinguisher. Opaque values
and RD type 0/type 2 encodings must remain distinct even when their displayed
strings are equal. The published `peer_rd`, peer hashes, and route hashes retain
their existing representation; these cache keys are internal. RD encoding is
described in [RFC 4364 sections 4.1–4.2](https://datatracker.ietf.org/doc/html/rfc4364#section-4.1).

## Scope and verification

The correction supplies negotiated state to legacy IPv4 and MP_REACH/MP_UNREACH
callers. It does not add PathID decoding to EVPN, VPLS, SR Policy, FlowSpec,
MCAST-VPN/MVPN, or RTC decoders that currently lack it, or change SAFI 72 framing.

Regression tests cover the negotiation matrix, policy/ASN flag independence,
family collisions, peer isolation, Loc-RIB replacement and merging, PeerDown,
raw distinguisher collisions, and public identifier compatibility. Wire tests
check the prefix and PathID produced by legacy and MP route processing.
Producer-level regressions block route publication and verify that PeerDown and
replacement PeerUp cannot overtake it or change the decoding state of its later
MP attributes. They cover both RIB directions, Loc-RIB table names, and a first
ADD-PATH route immediately after PeerUp. A separate blocked-installation test
checks that readiness is not exposed before the properties are installed.
Combined wire regressions cover negotiated ADD-PATH with D-PATH in VPNv4
announcements and withdrawals in both monitored directions, malformed D-PATH
treat-as-withdraw, and genuine versus false End-of-RIB markers. A unicast
withdrawal also checks the negotiated format without VPN parser fallback.
These are local parser/producer checks; real-router and live-broker acceptance
are separate validation activities.
