# BGP-LS VPN NLRI framing

AFI 16388 / SAFI 72 carries BGP-LS VPN topology information. Both
MP_REACH_NLRI announcements and MP_UNREACH_NLRI withdrawals use the same
decoder and the layout in [RFC 9552 section 5.2, Figure 6](https://www.rfc-editor.org/rfc/rfc9552.html#section-5.2):

```text
NLRI Type (2 bytes)
Total NLRI Length (2 bytes)
Route Distinguisher (8 bytes)
Link-State NLRI body (variable)
```

Total NLRI Length includes the eight-byte Route Distinguisher (RD) and the
body. It excludes the Type and Length fields. `VPNElement.Length` preserves
that wire value; the body passed to a typed decoder is `Length - 8` bytes.
Each entry in a batch has its own header, RD and body.

When ADD-PATH applies to this address family, a four-byte Path Identifier
precedes each entry's Type field, as specified in
[RFC 7911 section 3](https://www.rfc-editor.org/rfc/rfc7911.html#section-3).
The Path Identifier is not included in Total NLRI Length.

The decoder checks the complete header, minimum RD length and declared
element boundary before accessing RD or body bytes. Existing typed body
validators remain in use. A malformed trailing entry returns an error
without partial results; it cannot borrow bytes beyond its declared body
to complete a typed object. RD types 0, 1 and 2 use the existing RD parser.

Unknown NLRI types are preserved as opaque objects, following RFC 9552
section 5.2. Their body bytes are copied and published as hexadecimal
`LSOpaque.nlri` data, with SAFI 72 and the RD represented separately. An
unknown type with an empty body still carries an RD and has Length 8.
Type 7 remains opaque under SAFI 72. This framing correction does not add
typed VPN Inter-AS support or define VPN half-link correlation semantics;
those remain the subject of [issue #478](https://github.com/sbezverk/gobmp/issues/478).

The former `RD -> Type -> Length -> body` encoding is invalid for this
address family and is intentionally unsupported. All inputs are interpreted
using the RFC layout; there is no legacy-format detection or fallback.
The encodings can overlap, so guessing the format could silently corrupt a
valid NLRI. Producers and synthetic fixtures that emitted RD-first entries
must correct both the field order and the length calculation.
