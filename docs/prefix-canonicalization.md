# Canonical route prefixes

Ordinary and labeled-unicast NLRI parsers clear unused low bits in the last
prefix octet before formatting the address or generating route identity. RFC 4271
Section 4.3 leaves these padding bits unspecified; they do not distinguish routes.
For labeled unicast, the mask uses the IP prefix length after subtracting label
or withdrawal-compatibility bytes (RFC 8277 Section 2.2).

For example, the IPv4 /17 encodings `11 0a 01 00` and `11 0a 01 7f` both
publish `10.1.0.0/17` with the same identity. IPv6 receives the same treatment.
Default routes and octet-aligned prefixes retain their representation. Path IDs,
labels, parser validation, and the hash algorithm are unchanged. Masking is applied
only to an owned prefix copy; input and raw UPDATE bytes are preserved. The shared
base decoder also canonicalizes its multicast and BGP-LS prefix-descriptor callers.

## Compatibility and existing state

Previously published noncanonical prefixes can have different addresses and route
keys from their corrected canonical representation. Consumers retaining route
state must rebuild or reconcile affected records from an authoritative replay or
fresh route snapshot. This change does not automatically remove stale records
and performs no external migration. Already canonical prefixes keep their keys.

Rolling back restores the previous parsing behavior but does not reconcile records
written under either version; a rollback also requires state reconciliation. This
change does not address label-dependent labeled-unicast withdrawal keys, which
require a separate route-identity correction.
