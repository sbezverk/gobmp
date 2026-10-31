# Backpressure in the legacy Kafka validator

The Kafka consumer used by `cmd/validator` forwards each consumed record
synchronously to its caller-owned `TopicChan`. A slow downstream therefore
stops further reads from that partition instead of creating a goroutine for
every pending message. No new message queue or arbitrary buffer is introduced.

The forwarding send also selects on the consumer stop channel. `Stop` can
cancel a delivery while downstream is stalled; it does not promise to drain
records already fetched into Sarama buffers. After `Stop` returns, the
consumer has no remaining forwarding goroutines or sends.

Record order is preserved within the consumed partition. There is no total
order guarantee across partitions. A closed `Errors` channel is disabled
while messages remain readable. A closed `Messages` channel ends the reader
without spinning or silently restarting from the oldest offset. Nil message
and error entries remain ignored.

## Shutdown and ownership

Use the existing lifecycle: call `Start` once, then `Stop` once after `Start`
has returned. Each reader closes its own Sarama partition consumer after
ceasing delivery. `Stop` signals cancellation, waits for reader cleanup and
then closes the parent consumer, as required by Sarama. Close errors are
logged; the public `Srv.Stop()` interface remains unchanged. The caller
continues to own `TopicChan`, which the consumer does not close.

Retry tickers are stopped when readers exit. An in-flight Sarama metadata or
consumer-creation request is still subject to the existing network/retry
configuration rather than direct stop-channel cancellation. No hard shutdown
deadline is introduced. Offset policy remains `sarama.OffsetOldest`, with no
consumer group or offset commits.

## Scope and companion change

This change applies only to the legacy consumer in
`pkg/kafka/kafka-consumer.go`. It does not change the collector publisher or
`cmd/validator_v2`.

The separate partition-coverage fix changes the same file and shares its
shutdown ownership correction. This independently based change still selects
the first partition; it does not address empty metadata or discovery of all
partitions. When combining the fixes, use this synchronous, stop-aware
forwarding loop in each partition reader. The combined implementation retains
partition-local ordering and independent cancellation.
