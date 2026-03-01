# Changelog

Message updates and major project changes should be documented here.

## [Unreleased]

### 2026-03-01

#### Added

- SR Policy Type I segment support (IPv6 node address with SRv6 endpoint behavior) per RFC 9831 Section 2.4.9
- SR Policy Type J segment support (IPv6 link-local adjacency with SRv6 SID) per RFC 9831 Section 2.4.10
- SR Policy Type K segment support (IPv6 Local/Remote adjacency with SRv6 SID) per RFC 9831 Section 2.4.11
- BGP-LS SR Policy TLV types 1201–1205 wired to NLRI Get methods for structured segment list access

#### Fixed

- Error wrapping and silent suppression of non-nil errors across BMP parsing pipeline
- Append aliasing in MCAST-VPN test helpers causing slice corruption
- `os.Exit` in cmd binaries bypassing deferred cleanup including glog buffer flush
- Exhaustive `ProtoID` switch cases across 8 packages to eliminate unreachable default branches
- Exhaustive `SpecType` switch in FlowSpec `UnmarshalJSON` for complete type coverage
- `typeSwitchVar` and `singleCaseSwitch` gocritic findings in SR and BGP packages
- Unnecessary type conversions in `pkg/base` Label and Prefix Descriptor types
- Missing godot periods on exported comments throughout codebase
- Unsafe type assertions in FlowSpec JSON unmarshaling replaced with comma-ok checks
- Dead `done` channel removed from validator store
- Bounds validation restored in `makePrefixSpec` after unparam linter regression

### 2026-02-28

#### Added

- SR Policy Type H segment support (IPv6 Local/Remote adjacency) per RFC 9831 Section 2.4.8

#### Fixed

- BMP Stats Report TLV count validation against actual buffer size to prevent silent truncation
- Bounds checks in BMP Peer Up message parser to prevent panic on truncated messages

### 2026-02-27

#### Added

- SR Policy Type G segment support (IPv6 link-local adjacency) per RFC 9831 Section 2.4.7

#### Fixed

- Timestamp decoding in BMP messages

### 2026-02-25

#### Added

- SR Policy Type F segment support (IPv4 Local/Remote adjacency) per RFC 9256 Section 2.4.6
- RFC 9012 Tunnel Encapsulation Attribute parsing
- EVPN Type 7 Multicast Membership Report Synch route support per RFC 9251 Section 9.2
- EVPN Type 10 S-PMSI A-D route support per RFC 9572 Section 3.2

### 2026-02-23

#### Added

- EVPN Type 8 Multicast Leave Synch route parsing per RFC 9251 Section 9.3
- EVPN Type 11 Leaf A-D route parsing per RFC 9572 Section 3.3
- SR Policy Type E segment support per RFC 9256 Section 2.4.5

#### Fixed

- L3VPN CIDR rounding that corrupted prefix lengths (e.g. /30 → /32)

### 2026-02-18

#### Added

- SR Policy Type C segment support (IPv4 node address + index) per RFC 9256 Section 2.4.3
- EVPN Type 6 Selective Multicast Ethernet Tag (SMET) route parsing per RFC 9251 Section 9.1

### 2026-02-08

#### Added

- EVPN Type 9 Per-Region I-PMSI A-D route support per RFC 9572 Section 3.1

### 2026-02-03

#### Added

- SR Policy Type B segment support (SRv6 SID only) per RFC 9831 Section 2.4.2

### 2026-01-16

#### Added

- L2VPN EVPN support (AFI 25, SAFI 70) per RFC 7432 and RFC 8365
  - All 11 EVPN route types (Types 1–5 per RFC 7432, Types 6–11 per RFC 9251/9572)
  - MAC/IP Advertisement, Inclusive Multicast, Ethernet Segment, IP Prefix routes
  - 14 test functions covering all route types

### 2026-01-08

#### Added

- Route Target Constraint support for IPv4 (AFI 1, SAFI 132) per RFC 4684
- Route Target Constraint support for IPv6 (AFI 2, SAFI 132) per RFC 4684

### 2025-12-16

#### Added

- Route Target Constraint support for IPv4 (AFI 1, SAFI 132) per RFC 4684
- Route Target Constraint support for IPv6 (AFI 2, SAFI 132) per RFC 4684

- RFC 8669 support: BGP Prefix-SID path attribute
- BGP Prefix-SID Label-Index TLV (Type 1)
- BGP Prefix-SID Originator SRGB TLV (Type 3)
- Enables Segment Routing prefix SID distribution via BGP
- RFC 7311 support: AIGP (Accumulated IGP Metric) path attribute
- AIGP attribute parsing for IGP metric propagation across AS boundaries
- AIGP field in BaseAttributes for traffic engineering applications
- Enables IGP metric visibility in large service provider networks
- RFC 9723 support: BGP Colored Prefix Routing (CPR) for SRv6
- Color Extended Community extraction in IPv4 and IPv6 Unicast prefixes
- Color field in UnicastPrefix message type for intent-aware routing
- RFC 5701 support: IPv6 Address Specific Extended Community
- IPv6-based Route Target and Route Origin extended communities
- Type 0x05 Extended Community parsing
- Enables IPv6 VPN route target filtering
- RFC 8097 support: BGP Prefix Origin Validation State Extended Community
- RPKI origin validation state extraction in Unicast and L3VPN prefixes
- Origin validation state field in UnicastPrefix and L3VPNPrefix message types
- Enables RPKI route validation monitoring and security analysis
- MCAST-VPN support for IPv4 (AFI 1, SAFI 5) per RFC 6514
- MCAST-VPN support for IPv6 (AFI 2, SAFI 5) per RFC 6514
- Support for all 7 MCAST-VPN route types: Intra-AS I-PMSI A-D, Inter-AS I-PMSI A-D, S-PMSI A-D, Leaf A-D, Source Active A-D, Shared Tree Join, Source Tree Join
- MVPN support for IPv4 (AFI 1, SAFI 129) per RFC 6514
- MVPN support for IPv6 (AFI 2, SAFI 129) per RFC 6514
- Support for all 7 MVPN route types (reusing MCAST-VPN parser): Intra-AS I-PMSI A-D, Inter-AS I-PMSI A-D, S-PMSI A-D, Leaf A-D, Source Active A-D, Shared Tree Join, Source Tree Join

### 2025-12-15

#### Added

- IPv4 Multicast support (AFI 1, SAFI 2) per RFC 4760
- IPv6 Multicast support (AFI 2, SAFI 2) per RFC 4760
- **VPLS Support (AFI 25, SAFI 65):** RFC 4761, RFC 6074, RFC 7854, RFC 4360 compliant
  - **RFC 4761** (VPLS-BGP): 17-byte NLRI format with VE ID and MPLS label blocks
  - **RFC 6074** (BGP-AD): 12-byte NLRI format with PE IPv4 address
  - **RFC 7854** (BMP): BMP protocol integration with error handling
  - **RFC 4360** (Extended Communities): Layer2 Info and Route Target parsing

  **NLRI Parsing:**
  - Length-based demultiplexing (12 vs 17 bytes)
  - MPLS label block calculation for RFC 4761
  - Both RFC formats supported in single BGP session

  **Extended Communities:**
  - Layer2 Info (Type 0x800A): Encapsulation type, control flags, MTU
  - Route Target (Types 0x0002, 0x0102, 0x0202): 3 RT format types
  - 19 encapsulation types (Ethernet, VLAN, ATM, Frame Relay, etc.)

  **Implementation:**
  - New package: `pkg/vpls/` with 9 test functions, 48 sub-tests
  - Performance benchmarks: 8 functions, <200 ns/op per operation
  - Message structure: `VPLSPrefix` in `pkg/message/types.go`
  - Kafka topic: `gobmp.parsed.vpls` (topic ID 17)

  **Test Results:**
  - 13 test functions, 52 tests
  - RFC 4761 parsing: 93.86 ns/op, 160 B/op
  - RFC 6074 parsing: 96.37 ns/op, 176 B/op
  - Route Target parsing: 12.73 ns/op, 32 B/op

### 2023-04-13

#### Changed

- SR value "prefix_sid" was previous configured with "omitempty" json tag option, this option is now removed. A valid
  SID index of 0 is now explicit in the json output.

### 2023-03-20

#### Fixed

- unresv\_bw\_kbps data structure was appending a slice, leaving initial 0 values and growing beyond the expected length.
  Updated function to index the slice to overwrite initial values and keep the expected length.
  [\#215](https://github.com/sbezverk/gobmp/issues/215)

### 2023-02-23

#### Added

- ls\_link attribute max\_link\_bw\_kbps BGP-LS TLV Type 1089 stored as an uint64 integer in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute max\_resv\_bw\_kbps BGP-LS TLV Type 1090 stored as uint64 integer in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute unresv\_bw\_kbps BGP-LS TLV Type 1091 stored as a slice of 8 uint64 integers in kbps
  [\#213](https://github.com/sbezverk/gobmp/issues/213)

#### Deprecated

- ls\_link attribute max\_link\_bw BGP-LS TLV Type 1089 statically set to 0
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute max\_resv\_bw BGP-LS TLV Type 1090 statically set to 0
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
- ls\_link attribute unresv\_bw BGP-LS TLV Type 1091 statically set to nil
  [\#213](https://github.com/sbezverk/gobmp/issues/213)
