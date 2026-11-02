# Empty FlowSpec next-hop

[RFC 8955 §4](https://www.rfc-editor.org/rfc/rfc8955.html#section-4) requires
advertised FlowSpec MP_REACH_NLRI next-hop length to be zero. IPv6 extends the same
mechanism in [RFC 8956 §§1–2](https://www.rfc-editor.org/rfc/rfc8956.html#section-2).
`MPReachNLRI.GetNextHop` now returns an empty string for length zero and only for
AFI 1/2, SAFI 133/134 (IPv4, IPv6, VPNv4 and VPNv6 FlowSpec).

Previously the producer published `invalid next hop address length: 0` as a
next-hop address for those valid advertisements. The existing `omitempty` schema
now omits `nexthop` and publishes `is_nexthop_ipv4: false`: an absent
next-hop has no address family. The producer also keeps this flag false for
withdrawals without a next-hop. Route hashes, specs and public method signatures
are unchanged.
Nonempty next-hop formatting and diagnostics for other invalid lengths/families
retain their existing behavior. This getter correction does not add stricter
wire validation for nonempty FlowSpec next-hops.

The typed FlowSpec JSON reader uses the complete schema-based decoder described
in [FlowSpec JSON decoding](flowspec-json.md). It accepts omitted optional fields,
including `nexthop`, and rejects present values with incompatible types. Common
metadata, peer identity, RIB policy flags, table name, storage identifiers and
component validation are preserved. The decoder assigns the receiver only after
successful decoding. Both the next-hop and full metadata/withdrawal regression
suites cover the integrated behavior.

Tests decode actual MP_REACH headers for all four families, normal IPv4/IPv6,
nonempty FlowSpec controls, invalid length 99 and unrelated empty families. Real
producer tests verify empty next-hops are omitted, the IPv4 next-hop flag is
explicitly false in the object and JSON, and typed JSON decoding preserves false
for all four FlowSpec families. Nonempty IPv4/IPv6 producer controls cover all
four families as well. Optional-field tests also preserve present-value
and type-error behavior. Replaying historical records or removing an already
stored diagnostic address is outside this change; consumers receive the corrected
representation for newly processed advertisements.
