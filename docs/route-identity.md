# Unicast and VPN route identity

A route's `hash` identifies its peer, address family, prefix and ADD-PATH path,
plus its Route Distinguisher for L3VPN. MPLS labels remain published forwarding
attributes; changing them replaces the existing route instead of creating a new
route key. An explicit withdrawal has the same hash as its announcement even
when its compatibility field carries no previous label.

This follows [RFC 8277 Section 2.4](https://www.rfc-editor.org/rfc/rfc8277.html#section-2.4)
for explicit withdrawals and [Section 2.5](https://www.rfc-editor.org/rfc/rfc8277.html#section-2.5)
for label replacement. ADD-PATH continues to distinguish paths as required by
[RFC 7911 Section 5](https://www.rfc-editor.org/rfc/rfc7911.html#section-5).

## Encoding and compatibility

The existing hash algorithm and component order remain unchanged. Its last
component is now:

| Record | Final hash component |
| --- | --- |
| Ordinary unicast, SAFI 1 or the legacy zero value | Empty string |
| Labeled unicast, SAFI 4 | Literal `safi=4` |
| L3VPN, SAFI 128 | Empty string |

The final empty component and its delimiter are retained. Consequently,
ordinary unicast hashes and previously empty-label VPN hashes remain unchanged.
Labeled unicast is distinct from ordinary unicast even in the same topic and
when a withdrawal has no labels. VPN identity already has a separate `l3vpn`
namespace. Address family is represented by the existing IPv4/IPv6 component;
RD type, RD value, peer, router and PathID remain part of the key.

Normal legacy and MP unicast, labeled-unicast and VPN records now populate the
existing `afi` and `safi` JSON fields, as End-of-RIB records already do. Public
field types, labels, topics and the router-based publication key are unchanged.
Consumers enforcing a strict schema should accept these family fields before
upgrading the producer. `UnicastPrefix.Equal` retains its existing payload
comparison behavior; it is not a comparison of canonical route identity.

All formerly nonempty-label VPN hashes change, including SRv6 routes with a
nonempty transposition value in the label field. Only previously empty-label
VPN/SRv6 hashes are preserved. An explicitly supplied nonempty `Hash` is not
recomputed. End-of-RIB records still have no route hash.

## Persistent consumer state migration

The producer does not own downstream databases or their checkpoints and cannot
migrate them automatically. Do not resume a persistent store built with the old
label-dependent keys against the new producer without a state transition.
Otherwise, old active records can remain alongside the new keys, and mixed
historical announcements and withdrawals can recreate stale state.

1. Back up the affected consumer state, its broker checkpoints, producer
   version and configuration. Preserve a matching state/checkpoint pair for
   rollback; saving the producer binary alone is insufficient.
2. Prepare a clean generation of the affected routers' unicast and VPN views.
   Obtain a fresh complete BMP dump, including Peer Up and the relevant RIB
   views and families, from the upgraded producer. Keep this generation
   separate from the old key space and ensure old producer records are not
   interleaved into it. Rebuilding the whole affected view also avoids
   retaining earlier stale records whose old withdrawals lacked family data.
3. Track the dump and subsequent updates through the consumers' committed
   checkpoints. Observe each required peer/family's End-of-RIB, reconcile route
   counts and representative routes, and verify a label replacement followed
   by a withdrawal changes one route in the rebuilt store. Confirm other
   PathIDs and ordinary-unicast routes remain present. End-of-RIB is an
   observation, **not a delivery or commit barrier across topics**; the marker
   alone cannot establish that every consumer has applied the preceding data.
4. Switch readers to the verified new generation. Retain the old snapshot and
   checkpoints until the migration has been accepted. Historical replay into
   a stateful view must use one consistent key format or rebuild the view
   from an authoritative fresh snapshot.

For rollback, stop upgraded ingestion and select the previous producer version.
Restore an old consumer-state/checkpoint pair only when replay input is proven
to isolate old-format records, through an isolated source or a verified replay
boundary that excludes every record emitted during the upgraded-format
interval. Restoring the old binary and checkpoint does not rewrite hashes in
stored records. If that isolation or boundary cannot be established, roll back
the producer and build a new clean consumer generation from a fresh complete
BMP snapshot emitted by the rolled-back producer, establishing new checkpoints
and reconciling the generation before switching readers. Do not replay the
upgraded-format interval into a restored old-key store. No external migration
or router restart is performed by this change.

## Verification contract

Wire tests pass valid BGP frames and negotiated OPENs through the public BMP
producer into published JSON. They cover LU and VPN IPv4/IPv6, ADD-PATH,
combined/split topics, ordinary-unicast coexistence, label replacement and
compatibility withdrawals. A replay store keyed by the published hash must
replace one binding and delete that same binding while retaining other paths.
Golden vectors pin the existing ordinary-unicast and empty-label VPN hashes.
JSON round trips and End-of-RIB checks cover the additive family metadata.
Prefix-padding normalization is a separate change; these wire fixtures use
byte-aligned prefixes.
