# GitHub Copilot Instructions for gobmp

## Project Overview

`gobmp` is a Go implementation of the BGP Monitoring Protocol (BMP, RFC 7854) and related BGP
message parsing (RFC 4271, RFC 4760, RFC 9072, and many extension RFCs). It produces structured
messages consumed by downstream systems (Kafka, NATS, MongoDB connectors).

---

## Review Scope

When reviewing a pull request, **always produce a complete review of every changed file**.
Do not stop after 2–3 comments. Continue until every changed file has been reviewed and all
findings have been reported. Group related findings per file.

---

## Go-Specific Guidelines

### Error Handling
- All error messages in binary parsers must include both **"need N bytes"** and **"have M bytes"**
  (`len(b)-p`) at the point of failure — consistent with the pattern used throughout
  `pkg/bgp/mp-reach-nlri.go` and `pkg/bgp/bgp-update.go`:
  ```go
  fmt.Errorf("not enough bytes to unmarshal X: need %d bytes, have %d", needed, len(b)-p)
  ```
- Error messages must refer to the **remaining** bytes (`len(b)-p`), not the total buffer
  size (`len(b)`), which is misleading when `p > 0`.
- Never return a nil error with a nil value without explanation; always wrap with context.

### Bounds Checks
- Bounds checks that can never trigger (because a stricter guard already exists above them)
  are dead code and must be removed. Flag any unreachable `if p+N > len(b)` guards.
- Checks must be placed **before** the slice operation they protect, not after.

### Code Structure
- Table-driven tests are required for all new functionality. Each table entry must cover at
  least one happy path and one error/edge-case path.
- Test functions must not shadow package-level identifiers (e.g., naming a local variable
  `base` when the package imports `pkg/base`).
- Helper functions duplicating standard library functions (e.g., reimplementing
  `strings.Contains`) must be replaced with the standard library equivalent.

### Naming & Comments
- RFC references must cite the specific section, e.g., `// RFC 4760 §3` not just `// RFC 4760`.
- Exported symbols must have doc comments.
- Internal/unexported helpers used only in tests should be defined in `_test.go` files.

---

## Protocol-Specific Checks

### BGP OPEN (`pkg/bgp/bgp-open.go`)
- `HoldTime` must be validated: only `0` or `>= 3` are valid (RFC 4271 §4.2).
- `BGPID` of `0.0.0.0` is invalid (RFC 6286).
- RFC 9072 extended Optional Parameters path (`OptParamLen == 255` + `0xFF` sentinel) must have
  both positive (successful parse) and negative (truncated buffer) test coverage.

### MP_REACH_NLRI / MP_UNREACH_NLRI (`pkg/bgp/mp-reach-nlri.go`, `pkg/bgp/mp-unreach-nlri.go`)
- Every NLRI getter that dispatches on AFI/SAFI must return `NLRINotFoundError` (not a plain
  `fmt.Errorf`) for non-matching AFI/SAFI combinations.
- The `Reserved` byte (RFC 4760 §3) must be consumed/skipped; missing-reserved-byte checks
  must include the offset in their error message.

### Extended Communities (`pkg/bgp/extended-community.go`)
- `makeExtCommunity` enforces `len(b) == 8`; per-field bounds checks inside that function are
  unreachable and should be flagged for removal.

### BGP Update (`pkg/bgp/bgp-update.go`)
- All bounds-check errors in `UnmarshalBGPUpdate` must use the `need/have` pattern above.

---

## Test Coverage

- New code must include unit tests; aim for ≥ 70% line coverage on changed packages.
- Positive (happy path) tests are required for all new protocol parsing paths — negative-only
  tests do not verify that the feature actually works.
- When testing hash/digest functions (`GetBaseAttrHash`), document any algorithm assumptions as
  explicit contracts in a comment rather than silently hard-coding the expected output length.

---

## CI Requirements

The following must pass before merging:

- `go mod tidy && git diff --exit-code go.mod go.sum`
- `golangci-lint run --timeout=5m` (version v2.8.0)
- `go test -v ./...`

Flag any PR that introduces changes to `go.mod`/`go.sum` without a corresponding tidy step.
