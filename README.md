<p align="center">
  <img src="https://github.com/sbezverk/gobmp/blob/master/Hudson_Go_BMP_logo.png?raw=true" width="40%" height="40%">
</p>

<h1 align="center">goBMP</h1>

<p align="center">
  <strong>High-performance BGP Monitoring Protocol (BMP) Collector</strong>
</p>

<p align="center">
  <a href="https://github.com/sbezverk/gobmp/actions/workflows/cicd.yml">
    <img src="https://github.com/sbezverk/gobmp/actions/workflows/cicd.yml/badge.svg" alt="CI/CD">
  </a>
  <a href="https://codecov.io/gh/sbezverk/gobmp">
    <img src="https://codecov.io/gh/sbezverk/gobmp/branch/master/graph/badge.svg" alt="codecov">
  </a>
  <a href="https://goreportcard.com/report/github.com/sbezverk/gobmp">
    <img src="https://goreportcard.com/badge/github.com/sbezverk/gobmp" alt="Go Report Card">
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#supported-protocols">Supported Protocols</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#deployment">Deployment</a>
</p>

> **⚠️ Upgrading from an older version?**
> Publisher selection via `--dump=nats` and `--dump=kafka` has been removed.
> See the [Migration Guide](#migration-guide) for required configuration changes.

---

## Overview

goBMP is a production-ready implementation of the BGP Monitoring Protocol ([RFC 7854](https://tools.ietf.org/html/rfc7854)) collector written in Go. It receives BGP routing information from BMP-enabled routers, parses the data, and publishes structured messages to various outputs including Kafka, NATS, files, or stdout.

**Key Characteristics:**
- **RFC Compliant:** Implements RFC 7854 (BMP), RFC 8671 (BMP TLV), and numerous BGP extensions
- **Production Ready:** Battle-tested in large-scale network monitoring deployments
- **Flexible Deployment:** Run as standalone binary, Docker container, or Kubernetes workload
- **Multiple Outputs:** Kafka, NATS, file, console, or OpenBMP-compatible binary format
- **High Performance:** Efficient parsing and concurrent message processing

## Features

- ✅ **Comprehensive BGP Support:** IPv4/IPv6 Unicast, Labeled Unicast, L3VPN, EVPN, BGP-LS, SR Policy, FlowSpec
- ✅ **Segment Routing:** SR Policy segment types A–K (RFC 9256/9831), full SRv6 support with BGP-LS extensions (Flex Algo, Application-Specific attributes)
- ✅ **Multiple Publishers:** Kafka, NATS, file-based storage, console output
- ✅ **OpenBMP Compatibility:** RAW mode publishes binary messages compatible with OpenBMP consumers
- ✅ **Intercept Mode:** Transparent proxy mode for inserting into existing BMP pipelines
- ✅ **Topic Flexibility:** Separate or combined topics for IPv4/IPv6 address families
- ✅ **Active Mode:** Initiate outbound BMP sessions to routers — no inbound listener required
- ✅ **Performance Monitoring:** Built-in pprof endpoints for profiling and debugging
- ✅ **Kubernetes Native:** Ready-to-use deployment manifests included

## Supported Protocols

### BGP Address Families (AFI/SAFI)

| **Protocol** | **AFI/SAFI** | **Description** |
|--------------|--------------|-----------------|
| IPv4 Unicast | 1/1 | Standard IPv4 routing table |
| IPv6 Unicast | 2/1 | Standard IPv6 routing table |
| IPv4 Labeled Unicast | 1/4 | MPLS-labeled IPv4 prefixes |
| IPv6 Labeled Unicast | 2/4 | MPLS-labeled IPv6 prefixes |
| IPv4 Multicast | 1/2 | IPv4 multicast routing |
| IPv6 Multicast | 2/2 | IPv6 multicast routing |
| VPNv4 | 1/128 | MPLS L3VPN IPv4 |
| VPNv6 | 2/128 | MPLS L3VPN IPv6 |
| MCAST-VPN v4 | 1/5 | Multicast VPN for IPv4 |
| MCAST-VPN v6 | 2/5 | Multicast VPN for IPv6 |
| MVPN v4 | 1/129 | Multicast VPN (AFI 1) |
| MVPN v6 | 2/129 | Multicast VPN (AFI 2) |
| RTC v4 | 1/132 | Route Target Constraint for IPv4 |
| RTC v6 | 2/132 | Route Target Constraint for IPv6 |
| BGP-LS | 16388/71 | Link-State routing (IGP topology) |
| L2VPN VPLS | 25/65 | Virtual Private LAN Service |
| L2VPN EVPN | 25/70 | Ethernet VPN |
| SR Policy v4 | 1/73 | Segment Routing Policy for IPv4 |
| SR Policy v6 | 2/73 | Segment Routing Policy for IPv6 |
| FlowSpec v4 | 1/133 | Flow Specification for IPv4 |
| FlowSpec v6 | 2/133 | Flow Specification for IPv6 |

### Advanced Features

goBMP implements numerous protocol extensions including:
- **SR Policy Segments:** All 11 segment types (A–K) per RFC 9256 and RFC 9831 — MPLS label, SRv6 SID, IPv4/IPv6 adjacency and node variants
- **SRv6 Support:** BGP-LS extensions for SRv6 SIDs, Endpoint Behaviors, SID Structure TLVs
- **Flex Algorithm:** IGP Flexible Algorithm support in BGP-LS
- **Application-Specific Attributes:** Extended community and attribute parsing
- **BMP Statistics:** Full RFC 7854 and RFC 8671 statistics message support
- **FlowSpec:** Traffic filtering and DDoS mitigation rule distribution
- **EVPN Route Types 1–11:** All EVPN route types per RFC 7432, RFC 8365, RFC 9251, and RFC 9572

📋 **Complete RFC/Draft Support:** See [BMP.md](https://github.com/sbezverk/gobmp/blob/master/BMP.md) for detailed protocol compliance information.

📊 **Message Schemas:** Output message structures are defined in [`pkg/message/types.go`](https://github.com/sbezverk/gobmp/blob/master/pkg/message/types.go)

---

## Quick Start

### Option 1: Using Docker (Fastest)

Monitor live BGP data from RIPE RIS:

```bash
# Start goBMP collector
docker run --net=host sbezverk/gobmp --dump=console

# In another terminal, start RIPE RIS feed
docker run --net=host sbezverk/ris2bmp:1
```

Expected output:
```json
{"msg_type":0,"msg_hash":"some_hash","msg_data":{"action":"add","prefix":"1.1.1.0","prefix_len":24,"peer_ip":"2.2.2.2","peer_asn":65530,"nexthop":"3.3.3.3","as_path":[1,2,3],"origin":"igp"...}}
```

### Option 2: Build from Source

**Prerequisites:** Go 1.24 or later

```bash
git clone https://github.com/sbezverk/gobmp
cd gobmp
make gobmp
```

The statically-linked binary will be created at `./bin/gobmp`.

### Option 3: Kubernetes Deployment

```bash
kubectl create -f ./deployment/gobmp-standalone.yaml
kubectl get pods -l app=gobmp
```

---

## Usage Examples

### Basic Console Output
```bash
./bin/gobmp --source-port=5000 --dump=console --v=3
```

### Kafka Publishing
```bash
./bin/gobmp --source-port=5000 \
  --kafka-server=kafka.example.com:9092 \
  --kafka-topic-retention-time-ms=900000 \
  --split-af=true
```

### NATS Publishing
```bash
./bin/gobmp --source-port=5000 \
  --nats-server=nats://nats.example.com:4222
```

### Using a YAML Config File
```bash
./bin/gobmp --config=/etc/gobmp/config.yaml --v=3
```

### OpenBMP Binary Format (RAW Mode)
```bash
./bin/gobmp --source-port=5000 \
  --kafka-server=kafka.example.com:9092 \
  --bmp-raw=true \
  --admin-id=collector-01
```

---

## Configuration

### YAML Configuration File

goBMP supports an optional YAML configuration file specified with `--config`. CLI flags always take precedence over values in the file.

**Publisher selection is automatic** — there is no `publisher_type` field. goBMP infers the publisher from whichever server block is populated:
- `kafka_config.kafka_srv` present → Kafka publisher
- `nats_config.nats_srv` present → NATS publisher
- CLI `--dump` flag → Dump publisher (console or file)

Providing both `kafka_config` and `nats_config` in the same config file (or via CLI flags) is treated as an error only when goBMP must choose between Kafka and NATS (i.e., when `--dump` is not set). When `--dump=console` or `--dump=file` is used, any `kafka_config`/`nats_config` blocks are ignored.

**Kafka example (`config.yaml`):**
```yaml
bmp_listen_port: 5000
split_af: true
kafka_config:
  kafka_srv: "kafka.example.com:9092"
  kafka_tp_retn_time_ms: 900000
  kafka_topic_prefix: "prod"
  bmp_raw: false
  admin_id: "collector-01"
```

**NATS example:**
```yaml
bmp_listen_port: 5000
split_af: true
nats_config:
  nats_srv: "nats://nats.example.com:4222"
```

**All available fields:**
```yaml
# Listening
bmp_listen_port: 5000        # TCP port for BMP sessions (default: 5000)

# Performance monitoring (disabled when omitted or 0)
performance_port: 56767      # pprof port; any value > 0 enables collection

# BGP address-family handling
split_af: true               # true = separate v4/v6 topics (default: true)

# Kafka publisher (mutually exclusive with nats_config)
kafka_config:
  kafka_srv: "host:port"     # required to activate Kafka publisher
  kafka_tp_retn_time_ms: 900000
  kafka_topic_prefix: ""     # optional topic name prefix
  bmp_raw: false             # OpenBMP RAW mode
  admin_id: ""               # defaults to OS hostname

# NATS publisher (mutually exclusive with kafka_config)
nats_config:
  nats_srv: "nats://host:port"  # required to activate NATS publisher

# Dump publisher configuration (console/file); requires --dump on the CLI to activate
dump_config:
  file: "/path/to/dump.json"    # dump destination file used when --dump is enabled

# Active mode / speaker list
# When active_mode is true, goBMP dials out to the listed speakers instead of
# binding a listener. speakers_list must be non-empty; bmp_listen_port is ignored.
active_mode: false
speakers_list:
  - "192.0.2.1:57000"   # router-1
  - "192.0.2.2:57000"   # router-2
```

### Command-Line Parameters

### Network and Port Configuration

```
--config={path}
```
**Default:** none (disabled)

Path to a YAML configuration file. All settings in the file can be overridden by the corresponding CLI flags. See [YAML Configuration File](#yaml-configuration-file) above for the full field reference.

```
--source-port={port}
```
**Default:** 5000

TCP port where goBMP listens for incoming BMP sessions from routers. This is the primary listening port that routers should connect to for sending BMP messages.

```
--performance-port={port}
```
**Default:** 0 (disabled)

Port for performance monitoring using Go's pprof endpoints. Performance collection is **disabled by default** and must be explicitly enabled by specifying a port greater than 0. When enabled, pprof endpoints are available at `http://localhost:{port}/debug/pprof/`. Useful for debugging memory usage, CPU profiling, and goroutine analysis.

### Output and Publishing Configuration

goBMP has three publisher types: **dump** (console or file), **kafka**, and **nats**.

```
--dump={console|file}
```
**Default:** none (disabled)

Activates the dump publisher:
- `console`: Print JSON messages to stdout
- `file`: Write JSON messages to the file specified by `--msg-file`. If `--msg-file` is not provided, output falls back to console (stdout).

Kafka and NATS are separate publishers activated via `--kafka-server` and `--nats-server` respectively — do not use `--dump` to select them.

```
--msg-file={path}
```
**Default:** none (empty)

Full path and filename for storing processed messages when `--dump=file` is used. Each message is written as a JSON object on its own line.

> **Note:** If `--dump=file` is specified without `--msg-file`, goBMP falls back to console (stdout) output. To write to a file, always pair `--dump=file` with an explicit `--msg-file` path.

### Message Broker Configuration

> **Publisher inference:** goBMP selects the publisher automatically based on which server flag or config block is populated. Specifying both `--kafka-server` and `--nats-server` at the same time is an error.

```
--kafka-server={server:port}
```
**Default:** none (Kafka disabled)

Kafka broker address for publishing BMP messages. When specified, goBMP publishes parsed messages to topic-specific Kafka topics. Example: `--kafka-server=kafka.example.com:9092`

```
--kafka-topic-prefix={prefix}
```
**Default:** empty (no prefix)

Optional prefix prepended to all Kafka topic names. This is useful to isolate environments/tenants in a shared Kafka cluster.

Examples:
- default: `gobmp.parsed.peer`
- `--kafka-topic-prefix=prod`: `prod.gobmp.parsed.peer`

```
--kafka-topic-retention-time-ms={milliseconds}
```
**Default:** 900000 (15 minutes)

Kafka topic retention time in milliseconds. Topics are created with this retention policy to manage storage for high-volume BGP data. Adjust based on your storage capacity and retention requirements.

```
--nats-server={url}
```
**Default:** none (NATS disabled)

NATS server URL for publishing messages. Example: `--nats-server=nats://nats.example.com:4222`

### BMP Processing Modes

```
--split-af={true|false}
```
**Default:** true

Controls Kafka topic separation by address family:
- `true`: Separate topics for IPv4 and IPv6 (e.g., `gobmp.parsed.unicast_prefix_v4`, `gobmp.parsed.unicast_prefix_v6`)
- `false`: Combined topic for both address families (e.g., `gobmp.parsed.unicast_prefix`)

Useful for optimizing downstream consumers that only handle specific address families.

```
--bmp-raw={true|false}
```
**Default:** false

**RAW mode (OpenBMP compatibility):** When enabled, goBMP publishes BMP messages in OpenBMP v2 binary format without parsing the BGP content. This mode:
- Preserves the original BMP message in binary format
- Includes OpenBMP-compatible headers (version, collector hash, message length)
- Publishes to `gobmp.bmp_raw` topic
- Allows integration with existing OpenBMP-based pipelines

Use this when you need OpenBMP compatibility or want to defer BGP parsing to downstream consumers.

```
--admin-id={string}
```
**Default:** hostname

Collector administrator identifier used in RAW mode messages. This string is hashed (MD5) to generate the collector hash in OpenBMP binary headers. Useful for identifying which collector instance produced a message in multi-collector deployments.

### Logging and Debugging

```
--v={1-7}
```
**Default:** varies

Log verbosity level (1=errors only, 7=most verbose):
- `--v=1`: Critical errors only
- `--v=3`: Normal operational logging
- `--v=6`: **Debug mode** - includes hexadecimal dumps of BMP messages, useful for troubleshooting parsing issues
- `--v=7`: Maximum verbosity

Higher levels include all messages from lower levels.

---

## Deployment

### Kubernetes

goBMP includes production-ready Kubernetes manifests in the `./deployment` folder. The deployment exposes two ports:
- **Port 5000:** BMP session listener (configurable via `--source-port`)
- **Port 56767:** Performance monitoring (pprof endpoints)

**Deploy to cluster:**
```bash
kubectl create -f ./deployment/gobmp-standalone.yaml
```

**Verify deployment:**
```bash
kubectl get pods -l app=gobmp
# Expected output:
# NAME                     READY   STATUS    RESTARTS   AGE
# gobmp-765db4dcd9-6nh2c   1/1     Running   0          12h

kubectl get svc gobmp
# Expected output:
# NAME    TYPE        CLUSTER-IP      EXTERNAL-IP      PORT(S)                  AGE
# gobmp   ClusterIP   10.224.249.86   192.168.80.254   5000/TCP,56767/TCP       17h
```

**External access:** To connect routers from outside the cluster, ensure the service is exposed externally (LoadBalancer or NodePort). In the example above, routers would connect to `192.168.80.254:5000`.

### Docker

**Pre-built images:** Available on Docker Hub as `sbezverk/gobmp`

**Run standalone:**
```bash
docker run --net=host sbezverk/gobmp \
  --source-port=5000 \
  --kafka-server=kafka:9092 \
  --v=3
```

**Docker Compose example:**
```yaml
version: '3'
services:
  gobmp:
    image: sbezverk/gobmp
    network_mode: host
    command:
      - "--source-port=5000"
      - "--kafka-server=kafka:9092"
      - "--split-af=true"
      - "--v=3"
```

---

## Kafka Topics

When publishing to Kafka, goBMP creates the following topics (with `--split-af=true`):

| Topic | Description |
|-------|-------------|
| `gobmp.parsed.peer` | BMP Peer Up/Down events |
| `gobmp.parsed.unicast_prefix_v4` | IPv4 Unicast prefixes |
| `gobmp.parsed.unicast_prefix_v6` | IPv6 Unicast prefixes |
| `gobmp.parsed.l3vpn_v4` | L3VPN IPv4 routes |
| `gobmp.parsed.l3vpn_v6` | L3VPN IPv6 routes |
| `gobmp.parsed.evpn` | EVPN routes |
| `gobmp.parsed.ls_node` | BGP-LS Node NLRIs |
| `gobmp.parsed.ls_link` | BGP-LS Link NLRIs |
| `gobmp.parsed.ls_prefix` | BGP-LS Prefix NLRIs |
| `gobmp.parsed.ls_srv6_sid` | BGP-LS SRv6 SID NLRIs |
| `gobmp.parsed.sr_policy_v4` | SR Policy v4 NLRIs |
| `gobmp.parsed.sr_policy_v6` | SR Policy v6 NLRIs |
| `gobmp.parsed.flowspec_v4` | FlowSpec v4 rules |
| `gobmp.parsed.flowspec_v6` | FlowSpec v6 rules |
| `gobmp.bmp_raw` | RAW OpenBMP binary messages (when `--bmp-raw=true`) |

---

## Performance Monitoring

goBMP exposes Go's native pprof endpoints on the performance port (default: 56767):

```bash
# CPU profiling
curl http://localhost:56767/debug/pprof/profile?seconds=30 > cpu.prof

# Memory profiling
curl http://localhost:56767/debug/pprof/heap > mem.prof

# Goroutine analysis
curl http://localhost:56767/debug/pprof/goroutine > goroutine.prof

# Interactive profiling
go tool pprof http://localhost:56767/debug/pprof/heap
```

---

## Contributing

Contributions are welcome! goBMP is actively developed with ongoing work to expand protocol support and RFC compliance.

**Areas for contribution:**
- Additional BGP AFI/SAFI support
- Enhanced RFC compliance
- Performance optimizations
- Documentation improvements
- Bug fixes and testing

**Development workflow:**
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

See [CHANGELOG.md](https://github.com/sbezverk/gobmp/blob/master/CHANGELOG.md) for recent updates and release notes.

---

## License

This project follows the licensing terms of the original repository.

---

## Support & Resources

- **Mailing List:** [gobmp@googlegroups.com](mailto:gobmp@googlegroups.com) — announcements, Q&A, and general discussion
- **Issues:** [GitHub Issues](https://github.com/sbezverk/gobmp/issues)
- **Pull Requests:** [GitHub PRs](https://github.com/sbezverk/gobmp/pulls)
- **Documentation:** [BMP Protocol Details](https://github.com/sbezverk/gobmp/blob/master/BMP.md)
- **Message Schemas:** [types.go](https://github.com/sbezverk/gobmp/blob/master/pkg/message/types.go)

---

## Migration Guide

### Publisher Selection: `--dump=nats` and `--dump=kafka` removed

In previous versions the `--dump` flag accepted `nats` and `kafka` as values to select the message broker. These values are **no longer valid**. `--dump` is now restricted to `console` and `file` only.

Kafka and NATS publishers are now selected by specifying their server address directly. This makes the configuration unambiguous and removes the need for a separate publisher-type selector.

**Before (no longer works):**
```bash
# Old: selecting Kafka via --dump
gobmp --source-port=5000 --dump=kafka --kafka-server=kafka.example.com:9092

# Old: selecting NATS via --dump
gobmp --source-port=5000 --dump=nats --nats-server=nats://nats.example.com:4222
```

**After (current):**
```bash
# New: Kafka publisher is activated by providing --kafka-server
gobmp --source-port=5000 --kafka-server=kafka.example.com:9092

# New: NATS publisher is activated by providing --nats-server
gobmp --source-port=5000 --nats-server=nats://nats.example.com:4222
```

The same applies to YAML configuration files — there is no `publisher_type` field. The publisher is inferred automatically from whichever server block is populated:

```yaml
# Kafka (kafka_config.kafka_srv present → Kafka publisher selected automatically)
kafka_config:
  kafka_srv: "kafka.example.com:9092"

# NATS (nats_config.nats_srv present → NATS publisher selected automatically)
nats_config:
  nats_srv: "nats://nats.example.com:4222"
```

> **Note:** Specifying both `--kafka-server` and `--nats-server` at the same time (or having both blocks populated in the config file without `--dump`) is now an explicit error.

