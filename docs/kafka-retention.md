# Kafka topic retention

When goBMP creates a new Kafka topic, it sets `retention.ms` to the configured
`--kafka-topic-retention-time-ms` value (or `kafka_config.kafka_tp_retn_time_ms`
in YAML). The default is `900000` milliseconds, or 15 minutes. The publisher
accepts `-1` for unlimited time retention, `0`, and positive millisecond values;
values below `-1` and nonnumeric values are rejected. The existing YAML defaulting
uses `0` as an unset value and substitutes `900000`; use the explicit CLI flag
`--kafka-topic-retention-time-ms=0` to request zero retention.

This setting applies only to new topics. If a topic already exists, goBMP leaves
its configuration unchanged. Updating retention for an existing topic requires
an explicit administrative change outside goBMP. When
`--kafka-skip-topic-creation=true` is set, goBMP does not create or reconfigure
topics, so their existing retention policy applies.

Kafka can also remove records according to other configured limits, such as
`retention.bytes`; `retention.ms=-1` only disables time-based expiration.
