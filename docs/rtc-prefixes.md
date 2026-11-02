# Route Target Constraint prefixes

RTC messages retain the complete Route Target prefix in the optional
`route_target_prefix` JSON field. The value is lowercase hexadecimal, without a
`0x` prefix, in wire order. It includes the Extended Community type, subtype,
and any administrator/value bytes covered by the prefix. Encoding flags are
preserved; equal human-readable Route Targets can have different raw encodings.
Unused low bits in the last octet are cleared, so padding cannot create
multiple representations of the same prefix. Producing the message does not
change the decoded NLRI or its wire input.

Per [RFC 4684 Section 4](https://www.rfc-editor.org/rfc/rfc4684.html#section-4),
`length` counts the entire membership prefix, including its 32-bit Origin AS.
For a nondefault membership, the number of RT bits is `length - 32`. The field
contains exactly `ceil((length - 32) / 8)` RT octets. The Origin AS remains in
`origin_as`; it is not repeated in `route_target_prefix`.

| Membership | Relevant JSON fields |
| --- | --- |
| Default /0 | `length`, `origin_as`, and `route_target_prefix` omitted; `is_eor` false or omitted |
| Origin AS only /32 | `"length":32,"origin_as":65000`; RT fields omitted |
| Partial /64 | `"length":64,"origin_as":65000,"route_target_prefix":"0002fde8"` |
| Partial /65 | `"length":65,"origin_as":65000,"route_target_prefix":"0002fde880"` |
| Full /96 | `"length":96,"origin_as":65000,"route_target_prefix":"0002fde800000064","route_target":"65000:100"` |

These are field fragments, not complete messages. Zero Origin AS values retain
the existing `omitempty` behavior. A default membership is a route with zero
prefix bits; an End-of-RIB message is separately marked with `"is_eor":true`.

The same representation is published for announcements and withdrawals on the
existing RTC topics. The existing `route_target` field remains unchanged and
is emitted only for a complete /96 Route Target. Existing JSON without the new
field still decodes; consumers that reject unknown JSON fields must allow
`route_target_prefix`. Consumers distinguishing memberships can use Origin AS,
total length, and the raw RT prefix, alongside their existing peer/RIB context.
No route hashing, topic selection, partition keys, or backend state handling
changes are included.

The existing RTC parser accepts /1 through /31 even though RFC 4684 Section 4
requires every nondefault membership to include the complete Origin AS. That
independent validation issue is outside this representation change. Such
inputs do not acquire an RT-prefix field.
