# Four-octet AS capability validation

A BGP OPEN capability with code 65 must contain exactly four value octets,
as specified in [RFC 6793 section 3](https://www.rfc-editor.org/rfc/rfc6793#section-3).
The capability decoder now rejects every other declared length. Its error
identifies the capability code, offset, required size and supplied value size.
Existing truncation checks still reject values that extend beyond the available
input. Errors return no partially decoded capability map.

The validation applies to OPEN messages embedded in both Sent Open and Received
Open fields of a BMP PeerUp. Previously a short capability could pass the wire
parser and later panic while extracting the local ASN, terminating the collector.
Malformed wire data is now rejected through the existing parse-error path;
there is no broad panic recovery or silent acceptance of a malformed OPEN.

`OpenMessage.Is4BytesASCapable() (uint32, bool)` retains its signature and
first-entry semantics. A nil receiver, missing or empty capability list, nil
first entry, or first value shorter than four octets returns `(0, false)`.
It does not search later entries for a replacement. For compatibility with
manually constructed objects, values of at least four octets still return the
ASN encoded in their first four octets; this does not relax the wire decoder's
exact-length requirement. Valid parsed capabilities and valid OPEN behavior
remain unchanged. The peer-message handler retains its two-octet MyAS fallback
when the getter reports no usable AS4 capability.

Regression tests cover short and oversized wire values, truncation, a valid
four-octet ASN larger than 65535, malformed capabilities in each embedded OPEN,
malformed manually constructed objects, first-entry behavior and the peer
message's local-ASN selection. No capability codes, public schemas or unrelated
parser validation rules are changed.
