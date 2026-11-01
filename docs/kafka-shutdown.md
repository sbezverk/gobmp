# Kafka publisher shutdown

`PublishMessage` queues a message in Sarama. A successful return does not mean
that Kafka has acknowledged it.

Call `Stop` after all publishing calls have finished. The BMP server drains
its connection workers before stopping the publisher; the message player waits
for its publishing workers. Concurrent `PublishMessage` calls are supported
while the publisher is running. Publishing during or after `Stop` remains
outside this lifecycle contract. Repeated and concurrent `Stop` calls are safe:
all callers wait for the same complete producer and admin shutdown.

`Stop` now waits for the existing result-reader worker to finish
`sarama.AsyncProducer.Close`. That worker remains the single owner of producer
closure. Sarama drains the buffered messages and their delivery results during
Close; only then does goBMP close its ClusterAdmin client and return from Stop.
This prevents normal process exit from interrupting an outstanding tail message.

Producer and admin Close errors are logged. The Publisher interface retains its
existing `Stop()` signature, so shutdown errors are not returned to the caller.
Completion means that queued messages have reached a delivery success or a
terminal failure under Sarama's configured policy. It does not guarantee that
every message was delivered, nor add stronger acknowledgement or replication
semantics. See the pinned
[Sarama Close implementation](https://github.com/IBM/sarama/blob/v1.60.2/async_producer.go#L558-L580).

There is no separate shutdown timeout. Existing broker timeouts and retry
settings remain in effect. In particular, metadata retries can make shutdown
long when brokers are unavailable: goBMP configures up to 300 metadata retries
with a ten-second backoff, in addition to network operations and produce retries.
Operators should allow graceful termination enough time to finish. Forcefully
terminating the process can still interrupt delivery.

Regression tests use Sarama's MockBroker over local TCP. A test listener blocks
the actual Produce response write, verifying that Stop and admin closure wait
for an acknowledgement or terminal delivery error. A subprocess test confirms
that Stop cannot report completion while that response is withheld. The same
regressions fail against the previous early-return implementation. Separate
cases cover an unanswered Produce request and publishers finishing concurrently
before Stop. Repeated and concurrent Stop tests also hold producer completion
and admin closure separately, checking that every caller waits and the admin
closes once. These checks do not replace live-cluster or throughput acceptance.
