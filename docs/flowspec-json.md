# FlowSpec JSON decoding

`message.Flowspec` decodes common fields using its declared JSON schema and
handles the interface-valued `spec` components separately. Publisher announcements
and withdrawals retain peer identity, peer type, origin AS, RIB policy flags,
Loc-RIB filtering and table name. Storage identifiers, sequence and path ID also
survive decoding. Fields omitted by `omitempty`, including a withdrawal's
`nexthop`, are optional. Recognized fields with incompatible JSON types return
an error; the receiver is assigned only after successful decoding.

`action` and `spec_hash` must be present and decode as strings. For compatibility,
the existing acceptance of empty strings and JSON null is retained. This decoder
does not add semantic action or hash validation. Existing component checks remain:
numeric integral component types in [0,255], typed prefix/operator/value data,
and base64 decoding. Unknown numeric component types retain the existing logged
skip behavior; this change does not add component support or change wire parsing.

This is the JSON consumer contract, not a change to the FlowSpec encoding in
[RFC 8955 §4](https://www.rfc-editor.org/rfc/rfc8955.html#section-4),
[VPN FlowSpec §8](https://www.rfc-editor.org/rfc/rfc8955.html#section-8), or
[RFC 8956 §§2–3](https://www.rfc-editor.org/rfc/rfc8956.html#section-2).

The separate empty-next-hop correction includes a minimal optional `nexthop`
reader guard so it is independently usable. Both changes start from the same
upstream baseline and overlap in `Flowspec.UnmarshalJSON`. When combining them,
retain this complete schema decoder instead of restoring the old manual mapping
or adding a second next-hop decoder. Both regression suites must pass together.
This change alone leaves the producer's current next-hop representation intact.

`TestFlowspecJSONProducerRoundTrip` decodes real MP_REACH/MP_UNREACH bytes for
IPv4, IPv6, VPNv4 and VPNv6, invokes the actual producer and round-trips its JSON
across six peer views and announcements/withdrawals. Additional tests cover
storage fields, required-field compatibility, common-field type errors and
malformed/unknown components. Regression tests fail against the previous decoder.
No downstream replay or state mutation is performed.
