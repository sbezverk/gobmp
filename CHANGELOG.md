# Changelog

Message updates and major project changes should be documented here.

## [Unreleased]

### 2025-12-16

#### Added

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
