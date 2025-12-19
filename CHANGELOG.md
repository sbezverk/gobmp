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
