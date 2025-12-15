# Changelog

Message updates and major project changes should be documented here.

## [Unreleased]

### 2025-12-15

#### Added

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
