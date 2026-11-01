package kafka

import (
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/IBM/sarama"
)

func TestLegacyConsumerAllPartitions(t *testing.T) {
	tests := []struct {
		name       string
		partitions []int32
	}{
		{name: "single partition", partitions: []int32{0}},
		{name: "two partitions", partitions: []int32{0, 1}},
		{name: "noncontiguous partitions", partitions: []int32{3, 7}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := make(map[int32][]string)
			var want []string
			for _, partition := range test.partitions {
				value := fmt.Sprintf("partition-%d-oldest", partition)
				records[partition] = []string{value}
				want = append(want, value)
			}
			output, stop := startLegacyBrokerConsumer(t, records)
			got := make([]string, 0, len(want))
			for range want {
				got = append(got, receiveLegacyMessage(t, output))
			}
			stop()
			// Kafka defines order within a partition, not across partitions.
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("records = %v, want %v", got, want)
			}
		})
	}
}

func TestLegacyConsumerPartitionDiscoveryRetry(t *testing.T) {
	for _, first := range []string{"metadata error", "empty metadata"} {
		t.Run(first, func(t *testing.T) {
			var attempts atomic.Int32
			var childClosed atomic.Bool
			var masterClosed atomic.Bool
			opened := make(chan struct{})
			child := &legacyTestPartition{
				messages: make(chan *sarama.ConsumerMessage),
				errors:   make(chan *sarama.ConsumerError),
				close: func() error {
					childClosed.Store(true)
					return errors.New("partition close test error")
				},
			}
			master := &legacyTestMaster{
				partitions: func(string) ([]int32, error) {
					if attempts.Add(1) == 1 {
						if first == "metadata error" {
							return nil, errors.New("metadata unavailable")
						}
						return nil, nil
					}
					return []int32{4}, nil
				},
				consume: func(topic string, partition int32, offset int64) (sarama.PartitionConsumer, error) {
					if partition != 4 || offset != sarama.OffsetOldest {
						t.Errorf("ConsumePartition(%q, %d, %d), want partition 4/oldest", topic, partition, offset)
					}
					close(opened)
					return child, nil
				},
				close: func() error {
					if !childClosed.Load() {
						t.Error("master closed before partition consumer")
					}
					masterClosed.Store(true)
					return errors.New("master close test error")
				},
			}
			k := &kafka{stopCh: make(chan struct{}), master: master, topics: []*TopicDescriptor{{
				TopicName: "retry-topic", TopicChan: make(chan []byte),
			}}}
			stop := startLegacyTestConsumer(t, k)
			awaitLegacySignal(t, opened, "partition after metadata retry")
			stop()
			if !childClosed.Load() || !masterClosed.Load() {
				t.Fatalf("closed child/master = %t/%t, want both", childClosed.Load(), masterClosed.Load())
			}
		})
	}
}

func TestLegacyConsumerIndependentPartitionRetry(t *testing.T) {
	var attempts atomic.Int32
	var closed atomic.Int32
	available := make(chan struct{})
	recovered := make(chan struct{})
	stopCh := make(chan struct{})
	master := &legacyTestMaster{
		partitions: func(string) ([]int32, error) { return []int32{0, 1}, nil },
		consume: func(_ string, partition int32, offset int64) (sarama.PartitionConsumer, error) {
			if offset != sarama.OffsetOldest {
				t.Errorf("offset = %d, want OffsetOldest", offset)
			}
			if partition == 0 {
				if attempts.Add(1) == 1 {
					// Model a slow creation request: partition 1 must be able to
					// start before partition 0's first attempt even completes.
					select {
					case <-available:
						return nil, errors.New("partition temporarily unavailable")
					case <-stopCh:
						return nil, errors.New("stopped during partition creation")
					}
				}
				close(recovered)
			} else {
				close(available)
			}
			return &legacyTestPartition{
				messages: make(chan *sarama.ConsumerMessage),
				errors:   make(chan *sarama.ConsumerError),
				close:    func() error { closed.Add(1); return nil },
			}, nil
		},
		close: func() error {
			if got := closed.Load(); got != 2 {
				t.Errorf("closed partitions at master.Close = %d, want 2", got)
			}
			return nil
		},
	}
	k := &kafka{stopCh: stopCh, master: master, topics: []*TopicDescriptor{{
		TopicName: "independent-retry", TopicChan: make(chan []byte),
	}}}
	stop := startLegacyTestConsumer(t, k)
	awaitLegacySignal(t, available, "available partition")
	awaitLegacySignal(t, recovered, "recovered partition")
	stop()
}

func TestLegacyConsumerStopDuringRetry(t *testing.T) {
	for _, stage := range []string{"metadata error", "empty metadata", "partition error"} {
		t.Run(stage, func(t *testing.T) {
			attempted := make(chan struct{})
			var calls atomic.Int32
			var closed atomic.Bool
			markAttempt := func() {
				if calls.Add(1) == 1 {
					close(attempted)
				}
			}
			master := &legacyTestMaster{
				partitions: func(string) ([]int32, error) {
					if stage == "partition error" {
						return []int32{0}, nil
					}
					markAttempt()
					if stage == "metadata error" {
						return nil, errors.New("metadata unavailable")
					}
					return nil, nil
				},
				consume: func(string, int32, int64) (sarama.PartitionConsumer, error) {
					markAttempt()
					return nil, errors.New("partition unavailable")
				},
				close: func() error { closed.Store(true); return nil },
			}
			k := &kafka{stopCh: make(chan struct{}), master: master, topics: []*TopicDescriptor{{
				TopicName: "stop-retry", TopicChan: make(chan []byte),
			}}}
			stop := startLegacyTestConsumer(t, k)
			awaitLegacySignal(t, attempted, stage)
			stop()
			if !closed.Load() {
				t.Fatal("master was not closed")
			}
		})
	}
}
