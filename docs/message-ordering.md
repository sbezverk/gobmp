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
are skipped with a diagnostic. They are not buffered or allowed to block a later
Peer Up. Once that initial Peer Up has been processed, existing peer-identity and
capability handling continues unchanged.

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

The producer observes stop between messages and returns when its input channel
is closed. `PublishMessage` has no cancellation parameter: a call already in
progress must return before that producer can stop. This change does not add a
hard shutdown deadline or guarantee that connection closure drains all accepted
frames to a broker.

Regression tests exercise actual BMP wire frames through the parser/producer
pipeline, including announcement, withdrawal, explicit End-of-RIB and Peer Down,
plus RAW byte order, early traffic, queue closure, stop and independent producers.
These checks do not substitute for real-router or live-broker load acceptance.
