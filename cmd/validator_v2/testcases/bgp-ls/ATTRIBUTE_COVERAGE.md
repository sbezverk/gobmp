# BGP-LS validator_v2 attribute coverage

The JSON files in this directory are validator_v2 cases. Their `inject.body`
values are copied from the unchanged injector fixtures in `fixtures/`. The
`expect.contains` sections check the GoBMP Kafka message fields that correspond
to the injected NLRI and attributes. Dynamic Kafka metadata such as hashes and
timestamps is not compared.

## Attributes without a direct Kafka field

These fixture values do not currently have a dedicated named field in the
corresponding GoBMP event. The validator cases therefore do not assert a named
field for them.

| Fixture | Attribute | Notes |
|---|---|---|
| `link_isis_attributes.json` | L2 bundle member attributes | `LSLink` has no field for the bundle member data; TLV 1098 is treated as modeled, so it is not retained in `unknown_bgp_ls_tlvs` either. |
| `link_isis_attributes.json` | Graceful Link Shutdown | No dedicated `LSLink` JSON field. |
| `link_isis_attributes.json` | RTM capability | No dedicated `LSLink` JSON field; check `unknown_bgp_ls_tlvs` for raw retention if this value needs coverage. |
| `link_isis_attributes.json` | Extended Administrative Groups | No dedicated `LSLink` JSON field; the raw TLV may be retained as an unknown TLV. |
| `link_isis_attributes.json` | Peer Node, Peer Adjacency, and Peer Set SIDs | GoBMP maps these into named fields for BGP links. This fixture uses IS-IS, so those named fields are not populated. |
| `prefix_ipv6_ospfv3_srv6_attributes.json` | Trailing bytes of the four-byte Prefix Attribute Flags value | The current protocol-specific flags object represents the defined flag bits, not the complete original octet sequence. The fixture's final `0x01` byte is not represented by a named output bit. |
| `srv6_sid_isis_attributes.json` | Unknown path-attribute TLV 65006 | The SRv6 SID Kafka event type has no `unknown_bgp_ls_tlvs` field. |

The two link fixtures each inject two SRLG values. The captured GoBMP runs
showed only the first value when bgpinjector emitted repeated TLVs. The cases
assert the first SRLG and leave the second as an observed injection/encoding
gap until a run confirms both values arrive in one TLV and appear in Kafka.

`node_isis_attributes.json` sets SRv6 capability `flags` to `1`, which sets a
reserved bit. The case checks GoBMP's currently decoded `o_flag: false`; the
fixture should use a valid flag value before this is treated as positive
coverage of an enabled SRv6 capability.

## Kafka topic prerequisite

The four Kafka containers in `tb_xrd_26.4.1_injector_multinode_kafka.yml`
must create `gobmp.parsed.sr_policy_candidate_path`. Kafka auto-creation is
disabled in this testbed, so the SR Policy cases cannot publish successfully
without that topic. The topic has been added to the testbed's configured topic
list.

## Execution

The testcase runner scans only the directory passed as `TESTCASE_DIR`, so use
`cmd/validator_v2/testcases/bgp-ls` to run these cases. The `fixtures/`
subdirectory remains a collection of injector request bodies and is not scanned
as validator cases. These cases omit per-case cleanup because the current
runner waits 60 seconds before sending a cleanup request; reset the isolated
testbed after the suite to clear the injected routes.
