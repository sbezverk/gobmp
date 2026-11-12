# BGP-LS path identifiers in published messages

`LSNode`, `LSPrefix`, `LSSRv6SID` and `LSOpaque` preserve the decoded
ADD-PATH identifier in `PathID`, a `uint32` published as `path_id`.
`LSLink` already exposes the same field. This applies to announcements
and withdrawals, including SAFI 80's existing treat-as-withdraw paths.

For example, two advertisements for one NLRI with Path Identifiers 7 and 9
produce two records carrying `path_id: 7` and `path_id: 9`. A later withdrawal
of Path Identifier 7 carries `action: "del"` and `path_id: 7`; a consumer can
retain path 9. This follows the path identity and replacement rules in
[RFC 7911 sections 2 and 5](https://www.rfc-editor.org/rfc/rfc7911.html#section-2).

Path Identifiers are assigned within a BGP session. Consumers must combine
the peer/session, address family and RIB view, NLRI identity, and Path
Identifier when tracking route paths. Structural graph identifiers such as
`local_node_hash` and `remote_node_hash` retain their existing meaning;
they are not per-path keys and are not changed by this fix.

The JSON field uses `omitempty`, matching `LSLink`: nonzero values are
published exactly, up to 4294967295; zero is omitted. Zero remains a valid
decoded value. Omission does not indicate whether ADD-PATH was negotiated,
so consumers requiring that distinction need the session's capability
context. Messages without ADD-PATH retain their existing JSON shape.

No publisher topics, numeric message identifiers or method signatures
change. Capability negotiation and wire parsing are unchanged.
The affected schemas use ordinary Go JSON encoding and decoding;
the new field survives their typed JSON round trips. Consumers that ignore
unknown fields remain compatible, but consumers that need separate paths
must include `path_id` in their own route state. Previously collapsed path
state requires replay or resynchronization; adding the field cannot recover
information discarded from older records. A rollback likewise does not
reconstruct that state.

## SAFI 72 limitation

The VPN dispatcher preserves `VPNElement.PathID` and RD separately in the
published message. The integrated [SAFI 72 framing correction](bgp-ls-vpn.md)
reads Type/Length before RD, with RD included in Length, following
[RFC 9552 section 5.2, Figure 6](https://www.rfc-editor.org/rfc/rfc9552.html#section-5.2).
`TestLSPathIDSAFI72Mapping` isolates Path Identifier publication from already
decoded objects. `TestProcessMPUpdateSAFI72Wire` separately checks real-wire
decoding and RD publication for announcements and withdrawals with and without
ADD-PATH. Typed VPN Inter-AS support remains outside this change.
