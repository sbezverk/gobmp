# goBMP — Project Analysis

## What It Is

**goBMP** is a **BGP Monitoring Protocol (BMP) collector** written in Go. It:

- Listens for BMP sessions from routers (RFC 7854)
- Parses BMP messages and BGP NLRIs
- Publishes structured (JSON) or raw binary messages to Kafka, NATS, file, or stdout

It is intended for production use in BGP/network monitoring pipelines.

---

## Architecture Overview

```
Routers (BMP) → TCP :source-port → goBMP Server → Parser → Producer → Publisher (Kafka/NATS/File/Console)
                     (optional)   → Intercept → TCP :destination-port (e.g. OpenBMP)
```

- **Entry:** `cmd/gobmp/gobmp.go` — flags, pprof server, publisher choice, `gobmpsrv.NewBMPServer(…)` and `Start()`.
- **Server:** `pkg/gobmpsrv/gobmpsrv.go` — one TCP listener per `source-port`; each connection gets a goroutine that:
  - Reads BMP common header + payload
  - Optionally opens a connection to `destination-port` (intercept mode) and forwards
  - Sends raw bytes to a **parser** and parsed `bmp.Message` to a **producer**
- **Parser:** `pkg/parser/parser.go` — consumes `[]byte`, parses BMP (common header, per-peer header, route monitor/stats/peer up/down/etc.), pushes `bmp.Message` to the producer. Can run in **raw mode** (no parsing, forward whole message).
- **Producer:** `pkg/message/producer.go` — takes `bmp.Message`, turns it into typed messages (e.g. `PeerStateChange`, `UnicastPrefix`, L3VPN, EVPN, BGP-LS, SR Policy, FlowSpec, VPLS, stats), JSON-encodes them, and calls the publisher.
- **Publisher:** `pkg/pub/publisher.go` — interface `PublishMessage(msgType, msgHash, msg)`. Implementations: Kafka (`pkg/kafka`), NATS (`pkg/nats`), file (`pkg/filer`), console (`pkg/dumper`).

So: **one TCP connection = one parser + one producer**, with channels between reader → parser → producer → publisher.

---

## Package Layout

| Area | Packages | Role |
|------|----------|------|
| **Entrypoints** | `cmd/gobmp`, `cmd/validator`, `cmd/player` | Main BMP server; validator (Kafka vs file); player (replay file → Kafka) |
| **BMP / BGP** | `pkg/bmp`, `pkg/bgp` | BMP headers, message types, BGP attributes, MP-NLRI |
| **Protocol parsers** | `pkg/unicast`, `pkg/l3vpn`, `pkg/evpn`, `pkg/mcastvpn`, `pkg/rtc`, `pkg/vpls`, `pkg/pmsi`, `pkg/multicast` | Per AFI/SAFI NLRI parsing |
| **BGP-LS / SR** | `pkg/bgpls`, `pkg/ls`, `pkg/sr`, `pkg/srpolicy`, `pkg/srv6`, `pkg/te`, `pkg/prefixsid`, `pkg/flowspec` | BGP-LS, Segment Routing, SRv6, TE, FlowSpec |
| **Processing** | `pkg/parser`, `pkg/message` | BMP → internal messages, hashing, routing to message types |
| **Output** | `pkg/pub`, `pkg/kafka`, `pkg/nats`, `pkg/filer`, `pkg/dumper` | Publisher abstraction and backends |
| **Utilities** | `pkg/validator`, `pkg/base` | Testing/validation and shared base types |

Message types and JSON shapes are centralized in `pkg/message/types.go` (and related files in `pkg/message/`).

---

## Binaries

| Binary | Purpose |
|--------|--------|
| **gobmp** | BMP collector: listen, parse, publish (Kafka/NATS/file/console); optional intercept and raw mode. |
| **validator** | Consume from Kafka and compare to a stored message file, or record messages to file (test harness). |
| **player** | Read BMP messages from a JSON file and publish them to Kafka (replay/testing). |

---

## Dependencies (`go.mod`)

- **Go 1.24**
- **IBM/sarama** — Kafka client
- **nats-io/nats.go** — NATS client
- **golang/glog** — logging
- **go-test/deep** — test comparison
- **sbezverk/tools** — internal helpers (e.g. hex dump, signal handling)

Transitive deps cover Kafka (snappy, lz4, SASL/Kerberos, etc.), NATS (nkeys), and crypto/net.

---

## Design Notes

1. **Concurrency:** Per-connection parser and producer; `parsingWorker` and `producingWorker` run in goroutines; no global parser lock.
2. **Safety:** Message length is validated before allocation (e.g. max 1MB per BMP message) to avoid panics on bad input.
3. **Flexibility:** Publisher is an interface; Kafka topics are split by address family when `split-af=true`; topic prefix and retention are configurable.
4. **OpenBMP:** Raw mode (`--bmp-raw=true`) publishes unparsed BMP in OpenBMP-style binary format with collector admin ID / hash.
5. **Performance:** pprof on a dedicated port; `GOMAXPROCS(1)` in main (single OS thread for process, still many goroutines).

---

## Testing

- Many `*_test.go` files across `pkg/`: BMP (headers, peer up/down), BGP (MP-NLRI, RFCs), protocol-specific (L3VPN, EVPN, BGP-LS, SR, FlowSpec, VPLS, etc.), parser, message producer, validator.
- RFC-oriented tests (e.g. `rfc8277_test.go`, `rfc9069_test.go`, `rfc9256_test.go`) suggest focus on standards compliance.

---

## Deployment

- **Docker:** Image `sbezverk/gobmp`; often run with `--net=host` for BMP port.
- **Kubernetes:** Manifests under `deployment/` (e.g. `gobmp-standalone.yaml`, `gobmp-player.yaml`).
- Default BMP listen port **5000**, pprof port **56767**.

---

## Summary

goBMP is a structured, protocol-rich BMP collector with a clear path from TCP → BMP parsing → BGP/NLRI handling → typed messages → pluggable publishers (Kafka, NATS, file, console). The codebase is organized by protocol and RFC, with multiple binaries for collection, validation, and replay, and is set up for production and CI (README badges, tests, deployment manifests).
