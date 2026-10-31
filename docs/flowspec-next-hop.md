# Empty FlowSpec next-hop

[RFC 8955 §4](https://www.rfc-editor.org/rfc/rfc8955.html#section-4) requires
advertised FlowSpec MP_REACH_NLRI next-hop length to be zero. IPv6 extends the same
mechanism in [RFC 8956 §§1–2](https://www.rfc-editor.org/rfc/rfc8956.html#section-2).
`MPReachNLRI.GetNextHop` now returns an empty string for length zero and only for
AFI 1/2, SAFI 133/134 (IPv4, IPv6, VPNv4 and VPNv6 FlowSpec).

Previously the producer published `invalid next hop address length: 0` as a
next-hop address for those valid advertisements. The existing `omitempty` schema
now omits `nexthop`. Route hashes, specs and public method signatures are unchanged.
Nonempty next-hop formatting and diagnostics for other invalid lengths/families
retain their existing behavior. This getter correction does not add stricter
wire validation for nonempty FlowSpec next-hops.

The typed FlowSpec JSON reader previously required `nexthop` even though its
schema marks it optional. A minimal guard accepts an absent field, preserving
errors for a present incompatible type. This prevents the corrected announcement
JSON from newly failing its existing reader without depending on another branch.

The separate complete FlowSpec JSON fix overlaps this reader block. When combining
changes, retain the complete schema-alias decoder from that fix and the getter
change here; do not restore the old manual field mapping. The two changes are
independently buildable from upstream and both regression suites must pass after
the overlap is resolved. This minimal reader guard alone does not fix other lost
FlowSpec metadata or optional-field handling.

Tests decode actual MP_REACH headers for all four families, normal IPv4/IPv6,
nonempty FlowSpec controls, invalid length 99 and unrelated empty families. Real
producer tests verify empty next-hops are omitted and typed JSON decoding succeeds
for all four FlowSpec families. Optional-field tests also preserve present-value
and type-error behavior. Replaying historical records or removing an already
stored diagnostic address is outside this change; consumers receive the corrected
representation for newly processed advertisements.
