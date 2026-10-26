# End-of-RIB observations

goBMP publishes an `EndOfRIB` control message when a Route Monitoring payload
contains one of the two complete UPDATE forms specified in RFC 4724 section 2:

- A minimal empty legacy IPv4 UPDATE: no withdrawn routes, path attributes or NLRI.
- An UPDATE containing only one MP_UNREACH_NLRI attribute with its three-byte
  AFI/SAFI header and no withdrawn NLRI.

An ordinary withdrawal, attribute-only UPDATE, empty MP_REACH_NLRI, or empty
MP_UNREACH_NLRI mixed with another attribute or legacy route is not an EOR.
Nonempty routes in mixed UPDATEs continue through the existing route handlers.
Recognition precedes family-specific route decoding: all 27 supported MP family
combinations, legacy IPv4, and otherwise unknown AFI/SAFI values produce the
control event without attempting to decode an empty route.

## Interface

The internal publisher message type is `bmp.EndOfRIBMsg` (`24`). Existing message
identifiers and the publisher interface are unchanged; RAW remains `255`.
Kafka maps the event to `gobmp.parsed.end_of_rib` and initializes that topic. The
configured Kafka topic prefix also applies. NATS uses the same subject, covered
by the existing `gobmp.parsed.*` JetStream stream subject.

The JSON object has no route action or prefix. Its fields are:

| Fields | Meaning |
| --- | --- |
| `afi`, `safi` | Exact family identifiers from MP_UNREACH; `1`, `1` for legacy IPv4 |
| `router_hash`, `router_ip` | BMP speaker identity |
| `peer_hash`, `peer_rd`, `peer_ip`, `remote_bgp_id`, `peer_asn`, `peer_type` | Existing peer identity representation |
| `timestamp` | Per-peer BMP timestamp, using the existing string format |
| `is_adj_rib_in_post_policy`, `is_adj_rib_out_post_policy`, `is_adj_rib_out` | Monitored Adj-RIB direction and policy view |
| `is_loc_rib`, `is_loc_rib_filtered` | Loc-RIB and filtering flags |
| `table_name` | Loc-RIB table name, when available from PeerUp informational TLVs |

The publication key remains the router hash. A FlowSpec IPv4 EOR identifies
`"afi":1,"safi":133`; it contains no `"action":"del"` or `"spec_hash"`.
Table-name lookup uses the header's existing table key. This change does not
alter baseline cache identity or resolve collisions in formatted distinguishers.

## Compatibility and migration

The existing `is_eor` route-topic records are retained for legacy IPv4 and the
nine previously emitted MP markers: IPv4/IPv6 unicast, labeled unicast, L3VPN,
BGP-MUP, and EVPN. These records gain optional `afi` and `safi` fields; ordinary
route records omit those fields. Their existing actions and topics remain for
compatibility. Consumers must continue to interpret `is_eor` before treating
these compatibility records as route operations.

The universal event covers families that previously rejected empty route NLRI.
An empty FlowSpec MP_UNREACH no longer produces a synthetic withdraw-all route
or deletion key. Consumers that used that erroneous deletion behavior should
switch to the control event and maintain their own synchronization lifecycle.
The FlowSpec getters keep their existing empty-input return values; absence of
route NLRI alone does not establish EOR. Decode and publication errors retain
the existing logging behavior; this change adds no retry or durable-delivery
mechanism. A failed compatibility publication does not suppress the subsequent
attempt to publish the observed control marker.

## Observation, not a delivery barrier

Receipt of this control event means goBMP observed the marker. It does not prove
that another topic's route records have reached or been committed by a consumer.
This standalone change adds no producer ordering guarantee. Kafka/NATS topics
have no new global order, and the compatibility and control records describe the
same received marker rather than two synchronization completions.

Consumer-side table state, restart/session handling, stale-route cleanup and
coordination across subscriptions remain consumer responsibilities. Do not
classify every add as either snapshot or incremental solely from this event:
initial transfer and incremental updates can interleave under RFC 7854 section 9.

References: [RFC 4724 section 2](https://www.rfc-editor.org/rfc/rfc4724#section-2),
[RFC 7854 section 3.3](https://www.rfc-editor.org/rfc/rfc7854#section-3.3),
[RFC 7854 section 9](https://www.rfc-editor.org/rfc/rfc7854#section-9).
