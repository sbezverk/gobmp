# BGP-LS validator_v2 attribute coverage

The JSON files in this directory are validator_v2 cases. Their `inject.body`
values are copied from the unchanged injector fixtures in `fixtures/`. The
`expect.contains` sections check the GoBMP Kafka message fields that correspond
to the injected NLRI and attributes. Dynamic Kafka metadata such as hashes and
timestamps is not compared.

## Gaps and where to start

“No typed field” means the Kafka message does not expose a dedicated named
field. In several cases GoBMP still keeps the original TLV in
`unknown_bgp_ls_tlvs`, so the injected value is available as raw hex. Those are
schema/enrichment gaps, not evidence that the injector lost the value.

| Fixture value | Current result | Likely owner and starting point |
|---|---|---|
| `link_isis_attributes.json`: L2 bundle member attributes (TLV 1172) | No typed `LSLink` field; the complete TLV is retained in `unknown_bgp_ls_tlvs`. | **GoBMP typed mapping.** Add a field to `LSLink` in `pkg/message/types.go`, decode/populate it in `pkg/message/ls-link.go`, and mark 1172 modeled there once mapped. `collectUnknownBGPLSTLVs` in `pkg/message/ls-unknown-tlvs.go` currently preserves it because 1172 is not in `isModeledLinkTLV`. The injector has an encoder in `../bgpcollector/pkg/bgp_types/bgp_ls.go` (`TLVL2BundleMemberAttributes`, `L2BundleMemberAttributes`, and its marshal block around lines 1610–1630). **Correction:** this is TLV 1172, not 1098; 1098 is Link Name. |
| `link_isis_attributes.json`: Graceful Link Shutdown (TLV 1121) | No typed `LSLink` field; raw TLV is retained (empty value for this flag TLV). | **GoBMP typed mapping.** Add a `GracefulLinkShutdown` field and getter mapping in `pkg/message/types.go` and `pkg/message/ls-link.go`; then include 1121 in `isModeledLinkTLV`. The injector emits the flag in `../bgpcollector/pkg/bgp_types/bgp_ls.go` around lines 1662–1671. |
| `link_isis_attributes.json`: RTM capability (TLV 1105) | No typed `LSLink` field; raw TLV is retained, including its capability byte. | **GoBMP typed mapping.** Add a field/getter mapping in `pkg/message/types.go` and `pkg/message/ls-link.go`, then update `isModeledLinkTLV`. The injector encodes the value in `../bgpcollector/pkg/bgp_types/bgp_ls.go` around lines 1632–1643. |
| `link_isis_attributes.json`: Extended Administrative Groups (TLV 1173) | No typed `LSLink` field; raw TLV is retained. | **GoBMP typed mapping.** Add a field/getter mapping in `pkg/message/types.go` and `pkg/message/ls-link.go`, then update `isModeledLinkTLV`. The injector writes the group list as 32-bit values in `../bgpcollector/pkg/bgp_types/bgp_ls.go` around lines 1855–1863. |
| `link_isis_attributes.json`: Peer Node, Peer Adjacency, and Peer Set SIDs (TLVs 1101–1103) | These do not appear in the named peer-SID fields for this IS-IS link. GoBMP populates those fields only when `ProtocolID == BGP`; under IS-IS the TLVs remain in `unknown_bgp_ls_tlvs`. | **Protocol-specific GoBMP mapping / fixture intent.** The guard and mapping are in `pkg/message/ls-link.go` around lines 183–195; `isModeledLinkTLV` also treats 1101–1103 as modeled only for BGP. The injector encodes the TLVs, so this is not presently an injector-loss symptom. If the goal is to test named peer-SID output, use a BGP link fixture. If these TLVs are intended to map for IS-IS too, confirm the protocol semantics, then extend the GoBMP mapping. |
| `prefix_ipv6_ospfv3_srv6_attributes.json`: trailing three octets of Prefix Attribute Flags (TLV 1170; fixture value ends in `0x01`) | GoBMP's protocol flags object exposes decoded booleans, not the entire original four-octet value; current decoder passes only the first octet to the protocol decoder. | **GoBMP decoder/model.** `UnmarshalPrefixAttrFlags` in `pkg/bgpls/prefix-attr-tlv.go` around lines 124–142 slices `b[:1]`. The Kafka model is populated from that decoded object in `pkg/message/ls-prefix.go`; TLV 1170 is recognized as modeled, so its original bytes are not also retained as unknown. The injector serializes the fixture value into the TLV. Before adding a field, check which trailing bits have defined meaning for this protocol; retaining the raw four bytes is an option if round-trip visibility is required. |
| `srv6_sid_isis_attributes.json`: unknown path-attribute TLV 65006 | No `unknown_bgp_ls_tlvs` field is emitted on the SRv6 SID Kafka event, so this TLV is not available in that event. | **GoBMP event mapping/schema.** `LSSRv6SID` in `pkg/message/types.go` has no unknown-TLV field, and the producer in `pkg/message/ls-srv6-sid.go` maps selected known attributes without calling `collectUnknownBGPLSTLVs`. The parser retains the BGP-LS attribute TLVs on the update; the missing step is mapping them into the event. The injector's generic unknown-TLV encoder is in `../bgpcollector/pkg/bgp_types/bgp_ls.go`. To expose it, add a field and call unknown-TLV collection from the SRv6 SID producer, with a modeled-TLV predicate for the known SRv6 SID attributes. |
| `srv6_sid_bgp_attributes.json`: BGP Router ID descriptor (TLV 516) | It is not emitted as `igp_router_id`. That output is derived from IGP Router ID TLV 515; TLV 516 is a separate BGP Router ID descriptor. | **GoBMP event mapping/schema.** The SID path sets `IGPRouterID` via `GetSRv6SIDIGPRouterID()` in `pkg/message/ls-srv6-sid.go`; that getter reads the IGP Router ID in `pkg/srv6/srv6-sidnlri.go`. The distinct `GetBGPRouterID()` getter exists in `pkg/base/node-descriptor.go` around lines 155–160, but `LSSRv6SID` has no corresponding `bgp_router_id` field. If consumers need it, add a correctly named field and populate it from the local node descriptor. This is not an injector omission or an incorrect IGP Router ID decode. |

## Fixture and coverage notes

- **SRLG list:** both link fixtures inject two SRLG IDs. The current injector
  serializer writes all IDs into one TLV (`../bgpcollector/pkg/bgp_types/bgp_ls.go`,
  around lines 1963–1976), and GoBMP decodes each four-byte value in
  `pkg/bgpls/bgpls-nlri.go` around lines 649–662. A recent Kafka capture showed
  both values. The earlier observation of only the first value is not a
  confirmed current gap; consider asserting both IDs in the validator cases.
- **SRv6 capability flags:** `node_isis_attributes.json` sets `flags` to `1`,
  and the output has `o_flag: false`. GoBMP currently recognizes only bit
  `0x40` as `o_flag` in `pkg/srv6/srv6-capabilities.go`; that file also says
  “No RFC yet.” Thus the fixture does not exercise the enabled `o_flag`, but
  we cannot label bit 0 invalid based on the implementation alone. Agree on a
  valid flag encoding before changing the fixture; alternatively document this
  case as coverage of an unrecognized/non-O flag value.
- **Kafka topic prerequisite (infrastructure, not an attribute gap):** the
  four Kafka containers in `tb_xrd_26.4.1_injector_multinode_kafka.yml` must
  create `gobmp.parsed.sr_policy_candidate_path`. Kafka auto-creation is
  disabled in this testbed, and the topic is now included in its configured
  topic list.

## Execution

The testcase runner scans only the directory passed as `TESTCASE_DIR`, so use
`cmd/validator_v2/testcases/bgp-ls` to run these cases. The `fixtures/`
subdirectory remains a collection of injector request bodies and is not scanned
as validator cases. These cases omit per-case cleanup because the current
runner waits 60 seconds before sending a cleanup request; reset the isolated
testbed after the suite to clear the injected routes.
