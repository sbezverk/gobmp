<p align="center">
  <img src="https://github.com/sbezverk/gobmp/blob/master/Hudson_Go_BMP_logo.png?raw=true" width="40%" height="40%">
</p>

<h1 align="center">goBMP</h1>

<p align="center">
  <strong>High-performance BGP Monitoring Protocol (BMP) Collector</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#supported-protocols">Supported Protocols</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#deployment">Deployment</a>
</p>

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
- ✅ **Segment Routing:** Full SRv6 support with BGP-LS extensions (Flex Algo, Application-Specific attributes)
- ✅ **Multiple Publishers:** Kafka, NATS, file-based storage, console output
- ✅ **OpenBMP Compatibility:** RAW mode publishes binary messages compatible with OpenBMP consumers
- ✅ **Intercept Mode:** Transparent proxy mode for inserting into existing BMP pipelines
- ✅ **Topic Flexibility:** Separate or combined topics for IPv4/IPv6 address families
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
- **SRv6 Support:** BGP-LS extensions for SRv6 SIDs, Endpoint Behaviors, SID Structure TLVs
- **Flex Algorithm:** IGP Flexible Algorithm support in BGP-LS
- **Application-Specific Attributes:** Extended community and attribute parsing
- **BMP Statistics:** Full RFC 7854 and RFC 8671 statistics message support
- **FlowSpec:** Traffic filtering and DDoS mitigation rule distribution

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
{"action":"add","prefix":"223.104.44.0","prefix_len":24,"peer_ip":"80.81.195.241","peer_asn":49697,"nexthop":"80.81.195.241","as_path":[49697,41047,24961,33891,58453,9808,56048],"origin":"igp"...}
```

### Option 2: Build from Source

**Prerequisites:** Go 1.19 or later

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

### OpenBMP Binary Format (RAW Mode)
```bash
./bin/gobmp --source-port=5000 \
  --kafka-server=kafka.example.com:9092 \
  --bmp-raw=true \
  --admin-id=collector-01
```

### Intercept Mode (Transparent Proxy)
```bash
./bin/gobmp --source-port=5000 \
  --destination-port=5050 \
  --intercept=true \
  --kafka-server=kafka.example.com:9092
```

---

## Configuration

### Command-Line Parameters

### Network and Port Configuration

```
--source-port={port}
```
**Default:** 5000

TCP port where goBMP listens for incoming BMP sessions from routers. This is the primary listening port that routers should connect to for sending BMP messages.

```
--destination-port={port}
```
**Default:** 5050

Used only when `--intercept=true`. In intercept mode, goBMP receives BMP messages on `--source-port`, processes them, and forwards a copy to this destination port. This allows chaining goBMP instances or sending data to another BMP collector.

```
--performance-port={port}
```
**Default:** 56767

Port for performance monitoring using Go's pprof endpoints. Useful for debugging memory usage, CPU profiling, and goroutine analysis. Access via `http://localhost:56767/debug/pprof/`

### Output and Publishing Configuration

```
--dump={file|console|nats}
```
**Default:** none (disabled)

Controls where processed BMP messages are output:
- `file`: Write JSON messages to a file (see `--msg-file`)
- `console`: Print JSON messages to stdout
- `nats`: Publish messages to NATS server (see `--nats-server`)

Note: This is independent of Kafka publishing. You can use both simultaneously.

```
--msg-file={path}
```
**Default:** "/tmp/messages.json"

Full path and filename for storing processed messages when `--dump=file` is used. Each message is written as a JSON object.

### Message Broker Configuration

```
--kafka-server={server:port}
```
**Default:** none (Kafka disabled)

Kafka broker address for publishing BMP messages. When specified, goBMP publishes parsed messages to topic-specific Kafka topics. Example: `--kafka-server=kafka.example.com:9092`

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
--intercept={true|false}
```
**Default:** false

**Intercept mode:** When enabled, goBMP acts as a transparent proxy:
1. Receives BMP messages on `--source-port`
2. Processes and publishes them (to Kafka/file/console)
3. Forwards a copy to `--destination-port`

This allows inserting goBMP into an existing BMP pipeline without disrupting downstream collectors.

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
- Additional BGP AFI/SAFI support (VPLS, Multicast, etc.)
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

- **Issues:** [GitHub Issues](https://github.com/sbezverk/gobmp/issues)
- **Pull Requests:** [GitHub PRs](https://github.com/sbezverk/gobmp/pulls)
- **Documentation:** [BMP Protocol Details](https://github.com/sbezverk/gobmp/blob/master/BMP.md)
- **Message Schemas:** [types.go](https://github.com/sbezverk/gobmp/blob/master/pkg/message/types.go)

