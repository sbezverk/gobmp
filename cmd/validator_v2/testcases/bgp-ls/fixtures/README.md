# BGP-LS Gobmp validation fixtures

These are POST-ready `/v1/routes` announcement bodies intended to exercise
Gobmp's BGP-LS decoding through the injector and the BMP test environment. Each
case uses SAFI 71 (`address_family: "bgp-ls"`) and the testbed IPv6 next hop
`fd00:100::2`. For another lab, replace `next_hops` with the injector's
reachable BGP next hop, using the address family of that BGP session.

The cases combine many valid attributes into each route so a small manual run
can cover many decoder paths. They are generated and validated as injector
requests; they are not wired into Gobmp's CI yet. The current Gobmp CI has
RFC-focused Go tests, and these request fixtures are intended for manual
validation now and validator-v2 integration in a later step.

## Fixture coverage

| Fixture | Primary decoder coverage |
|---|---|
| `node_isis_attributes.json` | IS-IS Node NLRI; node flags/name/opaque value/areas; local IPv4 and IPv6 router IDs; SRv6 capability; MSD; SR algorithms; S-BFD; SR capabilities and local block; SRMS preference; Flexible Algorithm definition and sub-TLVs; unknown attribute TLV |
| `node_ospfv3_attributes.json` | OSPFv3 Node NLRI and router/area descriptors; node flags/name; local router IDs; MSD; S-BFD; unknown attribute TLV |
| `link_isis_attributes.json` | IS-IS Link NLRI with IPv4 and IPv6 interface descriptors and MT-ID; TE bandwidth/metrics/protection/MPLS mask; SRLG and opaque/link name; SR adjacency, LAN adjacency, and peer SIDs; delay/loss/bandwidth TE attributes; application-specific attributes; RTM capability; L2 bundle member; extended administrative groups; unknown TLV |
| `link_ospfv3_srv6_attributes.json` | OSPFv3 Link NLRI with IPv6 descriptors; adjacency and LAN adjacency SIDs; SRv6 End.X and LAN End.X SIDs with SID structure; TE attributes and application-specific attributes |
| `prefix_ipv4_isis_attributes.json` | IPv4 IS-IS Prefix NLRI; IGP flags, route tags, extended route tag, metric, opaque attribute, prefix attribute flags, label Prefix-SID, index Prefix-SID inside Range, source router ID, Flexible Algorithm Prefix Metric, unknown TLV |
| `prefix_ipv4_ospfv2_attributes.json` | IPv4 OSPFv2 Prefix NLRI and route type; OSPF IGP flags/forwarding address/source router ID; tags, metric, opaque attribute, Prefix-SID, OSPF Range, Flexible Algorithm Prefix Metric with external flag, unknown TLV |
| `prefix_ipv6_isis_attributes.json` | IPv6 IS-IS Prefix NLRI with MT-ID; index Prefix-SID and label Prefix-SID in a Range; source IPv6 router ID and Flexible Algorithm Prefix Metric |
| `prefix_ipv6_ospfv3_srv6_attributes.json` | IPv6 OSPFv3 Prefix NLRI and route type; OSPF flags/source router IDs; SRv6 Locator; Flexible Algorithm Prefix Metric; unknown TLV |
| `srv6_sid_isis_attributes.json` | Type 6 SRv6 SID NLRI from IS-IS; non-default MT-ID; endpoint behavior, algorithm/flags, SID structure, unknown TLV |
| `srv6_sid_bgp_attributes.json` | Type 6 SRv6 SID NLRI from BGP; BGP node descriptor; endpoint behavior and BGP PeerNode SID |
| `sr_policy_mpls_segment_types.json` | Type 5 SR Policy Candidate Path NLRI; candidate state/name and policy name; MPLS Binding SID; constraints (affinity, SRLG, bandwidth, disjoint and bidirectional groups, metric); SR-MPLS segment descriptor Types A and C–H; segment-list metric, bandwidth, identifier |
| `sr_policy_srv6_segment_types.json` | Type 5 SR Policy Candidate Path NLRI with IPv6 endpoint/originator; SRv6 Binding SID; constraints; SRv6 segment descriptor Types B and I–K; segment-list metric, bandwidth, identifier; unknown TLV |
| `sr_policy_disjoint_group_uint32.json` | SR Policy candidate path whose Disjoint Group Constraint carries the 4-octet group identifier `11` |
| `sr_policy_disjoint_group_pcep_object.json` | PCEP-origin SR Policy candidate path whose Disjoint Group Constraint carries a complete IPv4 PCEP ASSOCIATION object for a Disjoint Association (type 2), including its required Disjointness Configuration TLV |

The policy segment fixtures together cover the assigned segment descriptor
Types A through K. The raw `value_hex` on descriptor-bearing segment types is
the type-specific descriptor after the fixed SID field; it is not a complete
TLV. Opaque attribute strings are hex wire values, including the opaque
attribute's inner TLV header where the format requires it.

The two Disjoint Group Constraint fixtures show the mutually exclusive
identifier encodings: `group_id` is a four-octet integer, while
`pcep_association_object_hex` is the complete PCEP ASSOCIATION object, including
its four-octet PCEP object header. The PCEP example uses Association Type 2
(Disjoint Association) and includes the required Type 46 Disjointness
Configuration TLV.

Some less commonly exposed attributes in `link_isis_attributes.json`—notably
RTM Capability, L2 Bundle Member Attributes, and Extended Administrative
Groups—exercise Gobmp's generic BGP-LS TLV framing and raw TLV retention. The
current Gobmp package does not provide a dedicated typed accessor for each of
those TLVs, so their presence should be checked in the parsed raw TLV collection
rather than expected as a named JSON property.

## Scope notes

- BGP-LS-VPN SAFI 72 is omitted while support remains on hold.
- BGP-LS-SPF is omitted, as in the existing BGP-LS fixture set.
- The injector currently does not generate NLRI type 7 (Inter-AS Link), so it
  is not represented here.
- These are positive, valid advertisements. Malformed-input behavior belongs
  in unit tests rather than route-injection fixtures.

Example manual request:

```sh
curl --fail-with-body -sS -X POST http://127.0.0.1:8080/v1/routes \
  -H 'content-type: application/json' \
  --data-binary @testdata/injection_cases/gobmp/bgp_ls/node_isis_attributes.json
```
