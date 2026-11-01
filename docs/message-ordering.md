# BMP publication order

Each BMP connection has its own parser and producer. The producer processes
frames in input order and completes all `Publisher.PublishMessage` calls for one
frame before processing the next frame. An announcement followed by a withdrawal
therefore reaches the publisher in that order. Peer state changes and the existing
End-of-RIB outputs follow the same sequence.

This guarantee applies to publication calls within one connection. It does not
provide global ordering across connections or Kafka/NATS topics, broker delivery
acknowledgements, a cross-topic commit barrier, or a publisher flush guarantee.
It also does not change which UPDATEs are recognized as End-of-RIB.

## Traffic before Peer Up

[RFC 7854 section 3.3](https://www.rfc-editor.org/rfc/rfc7854.html#section-3.3)
places Peer Up before the initial Route Monitoring messages. Parsed Route
Monitoring and Statistics received before the connection's first valid Peer Up
are retained in a bounded per-connection buffer. Once that Peer Up has been
processed, the buffer is replayed in input order before later messages. If the
connection ends or receives Peer Down before Peer Up, the buffered messages are
discarded. A full buffer drops new pre-PeerUp messages with a diagnostic; it
cannot grow without bound.

RAW mode does not require Peer Up. Each received frame is encapsulated in the
OpenBMP envelope and published in input order with its BMP bytes preserved.

## Concurrency and shutdown limits

Different connections retain independent producers. A slow backend call on one
connection does not serialize the producers of other connections, although the
shared backend may impose its own resource limits.

Processing within one connection is sequential. Slow publication applies
backpressure instead of creating a goroutine for every frame; throughput for a
single busy connection may consequently differ. No throughput improvement is
claimed.

On EOF, connection error or server stop, the connection worker closes its parser
input and waits for it to drain, then closes producer input and waits for its
publication calls to finish. A complete frame handed to the parser is accepted.
All resulting valid messages finish their local publication calls before the
worker returns; the server waits for every worker before calling publisher.Stop.
Malformed/unsupported frames and pre-PeerUp traffic discarded because of
connection termination or buffer limits retain the existing skip behavior.
Incomplete trailing frames are never published.

The standalone parser/producer APIs still support an explicit stop signal. The
server uses input closure instead, so shutdown does not abort an accepted frame.
`PublishMessage` has no cancellation parameter: a blocked call must return before
that connection worker and server Stop can finish. No hard shutdown deadline or
broker-delivery/flush guarantee is added.

Regression tests exercise actual BMP wire frames through the parser/producer
pipeline, including announcement, withdrawal, explicit End-of-RIB and Peer Down,
plus RAW byte order, early traffic, queue closure, stop and independent producers.
Immediate EOF, truncated tails and server stop also verify that accepted parsed
and RAW publications finish before publisher shutdown, including a blocked final
publication. Parser closure leaves its output channel owned by the caller.
These checks do not substitute for real-router or live-broker load acceptance.
