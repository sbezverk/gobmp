# BGP Flowspec Variants — Comprehensive Analysis

**Scope:** Differences between IPv4, IPv6, VPNv4, and VPNv6 Flowspec  
**Reference RFCs:** RFC 8955 (IPv4 / VPNv4), RFC 8956 (IPv6 / VPNv6)  

---

## 1. Overview

BGP Flowspec is defined across two RFCs:

| RFC | Covers | AFI/SAFI pairs |
|-----|--------|----------------|
| **RFC 8955** (obsoletes RFC 5575, RFC 7674) | IPv4 unicast and VPNv4 filtering | (1, 133) and (1, 134) |
| **RFC 8956** (extends RFC 8955) | IPv6 unicast and VPNv6 filtering | (2, 133) and (2, 134) |

The four SAFI combinations:

| Variant | AFI | SAFI | Description |
|---------|-----|------|-------------|
| IPv4 Flowspec | 1 | 133 | Filters IPv4 packets in the global routing table |
| VPNv4 Flowspec | 1 | 134 | Filters IPv4 packets within MPLS/BGP VPN VRFs |
| IPv6 Flowspec | 2 | 133 | Filters IPv6 packets in the global routing table |
| VPNv6 Flowspec | 2 | 134 | Filters IPv6 packets within MPLS/BGP VPN VRFs |

These are **not interchangeable**. Each (AFI, SAFI) pair maintains its own distinct RIB. BGP treats each separately in path selection, policy, and protocol.

---

## 2. BGP Capability Advertisement

Capability Code 1 (Multiprotocol Extensions, RFC 4760) is used, with the specific AFI/SAFI pair indicating which variant is supported. Peers MUST advertise each variant they wish to exchange independently. A session can carry all four variants simultaneously over separate SAFI channels.

```
IPv4 Flowspec:  AFI=1, SAFI=133
VPNv4 Flowspec: AFI=1, SAFI=134
IPv6 Flowspec:  AFI=2, SAFI=133
VPNv6 Flowspec: AFI=2, SAFI=134
```

---

## 3. NLRI Encoding

### 3.1 Internet (non-VPN) Variants: IPv4 and IPv6

Both IPv4 and IPv6 Flowspec share the same outer NLRI envelope:

```
+-------------------------------+
|  length (0xnn or 0xfnnn)      |   1 or 2 bytes (RFC 8955 §4.1)
+-------------------------------+
|  NLRI value  (variable)       |   sequence of components
+-------------------------------+
```

**Length encoding** (identical for all four variants):
- Length < 240 bytes → encoded as 1 octet (`0xnn`)
- Length ≥ 240 bytes → encoded as 2 octets (`0xfnnn`), where the top nibble is `0xf` and the remaining 12 bits carry the actual length (max 4095)

### 3.2 VPN Variants: VPNv4 and VPNv6

The VPN variants prepend an 8-octet **Route Distinguisher** (RD) before the Flow Specification NLRI value. The length field covers both the RD and the NLRI value:

```
+--------------------------------+
|  length (0xnn or 0xfnnn)       |   includes both RD and NLRI value
+--------------------------------+
|  Route Distinguisher (8 bytes) |   per RFC 4364
+--------------------------------+
|  NLRI value  (variable)        |   same component encoding as non-VPN
+--------------------------------+
```

**Critical implication for parsers:** A VPN Flowspec parser **must** strip the 8-byte RD before passing the remaining bytes to the component parser. The component encoding that follows the RD is identical to the non-VPN version for the same AFI.

---

## 4. Component-by-Component Encoding Differences

Component type numbers are shared across all four variants. The **same type byte** identifies a component, but the **encoding and semantics** differ between IPv4 and IPv6 families.

### 4.1 Component Type Inventory

| Type | IPv4 Name | IPv6 Name | Encoding Difference |
|------|-----------|-----------|---------------------|
| 1 | Destination Prefix | Destination IPv6 Prefix | **Yes — significant** |
| 2 | Source Prefix | Source IPv6 Prefix | **Yes — significant** |
| 3 | IP Protocol | Upper-Layer Protocol | **Semantics differ** |
| 4 | Port | Port | None |
| 5 | Destination Port | Destination Port | None |
| 6 | Source Port | Source Port | None |
| 7 | ICMP Type | ICMPv6 Type | **Protocol differs (1 vs 58)** |
| 8 | ICMP Code | ICMPv6 Code | **Protocol differs (1 vs 58)** |
| 9 | TCP Flags | TCP Flags | None |
| 10 | Packet Length | Packet Length | None |
| 11 | DSCP | DSCP | None |
| 12 | Fragment | Fragment | **DF bit semantics differ** |
| 13 | *(unassigned)* | Flow Label | **IPv6 only — new type** |

VPNv4 uses IPv4 component encodings; VPNv6 uses IPv6 component encodings. The VPN prefix affects only the NLRI envelope (§3.2), not the components.

---

### 4.2 Type 1 — Destination Prefix / Type 2 — Source Prefix

This is the most significant structural difference between IPv4 and IPv6 Flowspec.

**IPv4 encoding** (`<type, length, prefix>`)
```
| type (1B) | prefix_len (1B) | prefix (ceil(prefix_len/8) bytes) |
```

**IPv6 encoding** (`<type, length, offset, pattern, padding>`)
```
| type (1B) | length (1B) | offset (1B) | pattern (variable) | padding (variable) |
```

- `length`: the N-th most significant bit where matching stops (i.e., the effective prefix length)
- `offset`: number of most significant bits to skip before matching starts (for embedded IPv4 address patterns)
- `pattern`: `ceil((length - offset) / 8)` bytes; only `(length - offset)` bits are significant
- `padding`: minimum bits to pad to octet boundary; MUST be 0 on encoding, MUST be ignored on decoding

**Constraint:** `length` MUST satisfy `offset < length < 129`, or `length = 0 AND offset = 0` (matches everything).

**Validation implication (RFC 8956 §5):** The validation rule that requires a destination prefix component only accepts components with `offset = 0`. A destination prefix with non-zero offset does **not** satisfy the validation rule and the Flow Specification MUST be treated as unvalidated.

**Example** — prefix `::1234:5678:9a00:0/65-104` is encoded as:
```
length=104, offset=65, pattern=5 bytes, 1 bit of padding
```

This offset mechanism is frequently used to match on the IPv4 portion embedded in IPv4-mapped IPv6 addresses.

---

### 4.3 Type 3 — IP Protocol vs Upper-Layer Protocol

**IPv4:** Matches the 8-bit IP Protocol field in the IPv4 header (RFC 791 §3.1).

**IPv6:** Matches the first Next Header value that is **not** an IPv6 extension header. In practice, extension headers (hop-by-hop options, routing, fragment, destination options) are skipped until the first "upper-layer" protocol value is found (RFC 8200 §4).

**Semantic implication:** On IPv4 this is always a simple single-field lookup. On IPv6, hardware and software implementations vary in their ability to walk extension header chains, especially for fragmented or ESP-encrypted packets. RFC 8956 §7 notes that routers with hardware limitations may be unable to enforce Type 3 matching when extension headers are present.

---

### 4.4 Types 7 and 8 — ICMP Type / Code vs ICMPv6 Type / Code

**IPv4:** Matches ICMP (protocol 1) type and code fields per RFC 792.

**IPv6:** Matches ICMPv6 (protocol 58) type and code fields per RFC 4443.

The numeric values are different protocols with different type/code spaces. For example, ICMP echo request is type 8 (IPv4), while ICMPv6 echo request is type 128. A parser that treats both variants identically would silently accept nonsensical filter rules.

---

### 4.5 Type 12 — Fragment

**IPv4 fragment bitmask** (RFC 8955 §4.2.2.12):
```
bit 7  bit 6  bit 5  bit 4  bit 3  bit 2  bit 1  bit 0
  0      0      0      0     LF     FF    IsF     DF
```
- `DF`: match if IPv4 Header Flags Bit-1 (Don't Fragment) is 1
- `IsF`: match if Fragment Offset ≠ 0
- `FF`: match if Fragment Offset = 0 AND MF flag is 1
- `LF`: match if Fragment Offset ≠ 0 AND MF flag is 0

**IPv6 fragment bitmask** (RFC 8956 §3.6):
```
bit 7  bit 6  bit 5  bit 4  bit 3  bit 2  bit 1  bit 0
  0      0      0      0     LF     FF    IsF      0
```
- `DF` **does not exist** in IPv6. Bit 0 MUST be 0 on encoding and MUST be ignored on decoding.
- `IsF`, `FF`, `LF` reference IPv6 Fragment Header (RFC 8200 §4.5) Fragment Offset and M flag.

A parser applying the IPv4 `DF` bitmask to IPv6 data would silently generate bogus filter rules.

---

### 4.6 Type 13 — Flow Label (IPv6 only)

This component type is **not assigned** in IPv4. It is defined only in RFC 8956 for IPv6:

```
<type (1 octet), [numeric_op, value]+>
```

Matches the 20-bit Flow Label field in the IPv6 header (RFC 8200 §3). Values SHOULD be encoded as 4-octet quantities (`numeric_op len=10`).

A parser that only knows Type 1–12 MUST return an error (or skip) if it encounters Type 13 on an IPv6-family NLRI.

---

### 4.7 Components Shared Without Difference

The following types have exactly the same encoding and semantics in all four variants:

| Type | Component |
|------|-----------|
| 4 | Port (matches source OR destination TCP/UDP port) |
| 5 | Destination Port |
| 6 | Source Port |
| 9 | TCP Flags |
| 10 | Packet Length |
| 11 | DSCP |

---

## 5. Validation Procedure

### 5.1 IPv4 Flowspec (AFI=1, SAFI=133)

Validated against IPv4 unicast routes received over SAFI=1 (RFC 8955 §6). A Flow Specification is feasible if:
- (a) A destination prefix component is embedded, AND
- (b) The originator of the Flow Specification matches the originator of the best-match unicast route for that prefix, AND
- (c) No more-specific unicast routes have been received from a different neighboring AS.

Rule (a) may be relaxed by explicit configuration.

### 5.2 VPNv4 Flowspec (AFI=1, SAFI=134)

Validated against IPv4 VPN routes received over SAFI=128 (RFC 8955 §6):
- Flow specifications received via SAFI=134 are validated against SAFI=128 routes.
- Flow Specifications received from **remote PE routers** are **accepted by default** — no unicast routing validation is performed for inter-PE traffic. This is a critical behavioral difference from the non-VPN case.
- Flow Specifications apply only to traffic that belongs to the VRF(s) into which they are imported (via Route Target matching, RFC 4364).
- Traffic received from a remote PE and switched via MPLS forwarding is **not subject** to filtering by default.
- Propagation is controlled by RT matching, the same mechanism as BGP/MPLS IP VPN routes.

### 5.3 IPv6 Flowspec (AFI=2, SAFI=133)

Same procedure as IPv4 (§5.1) but run against IPv6 unicast routes. One change to rule (a):

> (a) A destination prefix component **with offset=0** is embedded in the Flow Specification.

A destination prefix with non-zero offset does not satisfy validation rule (a).

### 5.4 VPNv6 Flowspec (AFI=2, SAFI=134)

Same as VPNv4 but for IPv6 VPN routes (SAFI=128 IPv6 VPN). Same PE-acceptance and RT-propagation behavior as VPNv4.

---

## 6. Traffic Filtering Actions (Extended Communities)

### 6.1 Common Actions (all four variants)

All four variants can carry the Traffic Filtering Action Extended Communities defined in RFC 8955 §7:

| Extended Community | Sub-Type | Description |
|-------------------|----------|-------------|
| `0x8006` | `0x06` | Traffic rate (bytes/second) |
| `0x800c` | `0x0c` | Traffic rate (packets/second) |
| `0x8007` | `0x07` | Traffic action (sample / terminal) |
| `0x8008` | `0x08` | RT Redirect AS-2octet |
| `0x8108` | `0x08` | RT Redirect IPv4 address |
| `0x8208` | `0x08` | RT Redirect AS-4octet |
| `0x8009` | `0x09` | Traffic marking (DSCP remark) |

### 6.2 IPv6-Specific Action (RFC 8956 §6.1)

IPv6 Flowspec (AFI=2, SAFI=133 and 134) adds one additional Traffic Filtering Action:

| Extended Community | Description |
|-------------------|-------------|
| `0x000d` | `rt-redirect-ipv6` — redirect to VRF using an IPv6-Address-Specific Route Target |

This uses the IPv6-Address-Specific Extended Community encoding (RFC 5701), which carries a 16-byte IPv6 global administrator and a 2-byte local administrator. IPv4 Flowspec cannot carry this community; it is meaningless on (AFI=1) sessions.

---

## 7. Ordering of Flow Specifications

### 7.1 IPv4 (RFC 8955 §5.1)

Comparisons proceed left-to-right by component type. For IP prefix components (types 1, 2), the more specific prefix has higher precedence; on equal specificity, the numerically lower IP value has higher precedence. For all other components, the comparison is lexicographic (memcmp). If common prefixes are equal, the longer string has higher precedence.

### 7.2 IPv6 (RFC 8956 §4)

The IPv6 ordering algorithm extends the IPv4 algorithm with one additional rule for prefix components:

> If two IPv6 prefix components have **different offsets**, the one with the **lower offset** has higher precedence (it matches more significant bits).

If offsets are equal, the IPv4 longest-prefix-match semantics apply. This offset comparison is performed before the prefix-length comparison.

---

## 8. Impact on gobmp: Current Gaps

### 8.1 `NLRIMessageType` — All Four Variants Return Code 27

**File:** `gobmp/pkg/bgp/mp-nlri.go`

```go
case afi == 1 && safi == 133: return 27  // IPv4 Flowspec
case afi == 2 && safi == 133: return 27  // IPv6 Flowspec
case afi == 1 && safi == 134: return 27  // VPNv4 Flowspec
case afi == 2 && safi == 134: return 27  // VPNv6 Flowspec
```

All four variants are indistinguishable after this function. Downstream consumers cannot apply the correct component parser (IPv4 vs IPv6 prefix encoding), strip the VPN Route Distinguisher, or route to AFI-specific message types.

**Suggested type codes:**

| Variant | Current | Suggested |
|---------|---------|-----------|
| IPv4 Flowspec (1, 133) | 27 | 27 (keep existing code) |
| IPv6 Flowspec (2, 133) | 27 | use a distinct, unused type code |
| VPNv4 Flowspec (1, 134) | 27 | use a distinct, unused type code |
| VPNv6 Flowspec (2, 134) | 27 | use a distinct, unused type code |

(Suggested values must be chosen so they do not conflict with any existing type codes in the `NLRIMessageType` switch statement in `mp-nlri.go`; no specific numeric values are mandated here.)

### 8.2 `UnmarshalFlowspecNLRI` — No AFI/SAFI Context

**File:** `gobmp/pkg/flowspec/flowspec_nlri.go`

`UnmarshalFlowspecNLRI(b []byte)` has no way to know whether the bytes are IPv4, IPv6, VPN, or not. Consequences:

1. **VPN RD not stripped:** VPN variants carry an 8-byte RD prefix. The caller (`mp-reach-nlri.go` or `mp-unreach-nlri.go`) must strip it before calling `UnmarshalFlowspecNLRI`. There is no verification that this is done correctly.

2. **Prefix components always parsed as IPv4:** `makePrefixSpec` uses `<type, length, prefix>` — the IPv4 format. When called for IPv6 Flowspec, the `length` field (which is an IPv6 bit-length) and the missing `offset` field will yield a corrupted `PrefixSpec`. There is no guard.

3. **Type 13 (Flow Label) rejected:** The default branch returns `fmt.Errorf("unknown Flowspec type")`, so any IPv6 Flow Label component causes a parse failure.

4. **Fragment bitmask not validated for IPv6:** The DF bit (bit 0) is valid in IPv4 but MUST be 0 in IPv6. No check is enforced.

5. **Type 3 semantics undocumented:** The `GenericSpec` that handles Type 3 has no comment indicating it represents "IP Protocol" for IPv4 and "Upper-Layer Protocol" for IPv6.

### 8.3 Recommended Changes

| Priority | Change | Justification |
|----------|--------|--------------|
| P1 | Assign distinct type codes for all four variants in `NLRIMessageType` | Downstream consumers must know the variant |
| P1 | Add `afi uint16, safi uint8` parameters to `UnmarshalFlowspecNLRI` | Required to select correct component parser |
| P1 | Implement IPv6 prefix component parser (`<length, offset, pattern>`) | Current parser silently corrupts IPv6 prefixes |
| P1 | Strip 8-byte RD before calling component parser for SAFI=134 | VPN parser currently reads RD as NLRI content |
| P2 | Add Type 13 (Flow Label) constant and parser | Required for RFC 8956 compliance |
| P2 | Validate Fragment DF bit is 0 for IPv6 | RFC 8956 §3.6: MUST be 0 |
| P3 | Implement IPv6 ordering algorithm (offset comparison) | RFC 8956 §4 |
| P3 | Add `rt-redirect-ipv6` (0x000d) to extended community decoder | RFC 8956 §6.1 |

---

## 9. Summary Table

| Aspect | IPv4 (1,133) | VPNv4 (1,134) | IPv6 (2,133) | VPNv6 (2,134) |
|--------|-------------|--------------|-------------|--------------|
| NLRI envelope | `<len, components>` | `<len, RD, components>` | `<len, components>` | `<len, RD, components>` |
| Prefix encoding (T1/T2) | `<len, prefix>` | same as IPv4 | `<len, offset, pattern, pad>` | same as IPv6 |
| Type 3 semantics | IP Protocol field | same as IPv4 | First non-EH Next Header | same as IPv6 |
| Type 7/8 | ICMP (proto 1) | same as IPv4 | ICMPv6 (proto 58) | same as IPv6 |
| Type 12 DF bit | Valid | same as IPv4 | Must be 0 | same as IPv6 |
| Type 13 Flow Label | Not defined | Not defined | Defined | Defined |
| Validation against | SAFI=1 unicast | SAFI=128 VPN; PE accepts by default | SAFI=1 IPv6 unicast; offset=0 required | SAFI=128 IPv6 VPN; PE accepts by default |
| rt-redirect action | AS/IPv4/4-oct RT | same as IPv4 | All IPv4 actions + `rt-redirect-ipv6` | All IPv4 actions + `rt-redirect-ipv6` |
| Ordering algorithm | RFC 8955 §5.1 | same as IPv4 | RFC 8956 §4 (offset comparison) | same as IPv6 |
| RD present | No | Yes (8 bytes) | No | Yes (8 bytes) |
