# Kafka partitions in the legacy validator

The Kafka consumer used by `cmd/validator` reads every partition returned by
the first successful, nonempty metadata lookup for each configured topic.
Each partition has one owned reader, so a partition whose consumer cannot yet
be created retries independently without delaying another partition.

Readers retain the existing `sarama.OffsetOldest` policy. They do not join a
consumer group, commit offsets or continuously discover partitions added after
startup. Restarting the validator reads retained records again. Kafka does not
define a total order across partitions.

An empty partition list is treated as temporarily unavailable metadata rather
than indexed. Metadata and partition-consumer creation failures retry on the
existing 200 ms cadence until stopped. Every retry ticker is stopped when its
owner exits.

## Shutdown and ownership

Use the existing lifecycle: call `Start` once, then `Stop` once after `Start`
has returned. `Stop` signals the readers, waits for them to exit and close
their own Sarama partition consumers, then closes the parent consumer. Close
errors are logged because the public `Srv.Stop()` signature has no error return.
The caller owns each `TopicChan`; the consumer does not close it.

Sarama requires child partition consumers to be closed before their parent.
The wait includes any in-flight metadata or consumer-creation request. Those
Sarama calls use the existing network/retry configuration and are not directly
cancellable through the stop channel. No hard shutdown deadline is introduced.

## Scope and companion change

This change applies only to the legacy validator consumer in
`pkg/kafka/kafka-consumer.go`. It does not change the collector publisher,
`cmd/validator_v2`, Kafka topic configuration or the public consumer interface.

The separate backpressure fix changes the same file and shares the shutdown
ownership correction. Until that fix is also applied, the legacy per-message
send goroutines remain: this partition-coverage change alone does not promise
ordered delivery, bounded pending sends or cancellation of a stalled downstream.
When combining the fixes, retain the stop-aware synchronous forwarding loop in
each partition reader. Only partition-local ordering is supported.
