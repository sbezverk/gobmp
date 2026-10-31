package kafka

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

func TestLegacyConsumerOrderedDelivery(t *testing.T) {
	for _, count := range []int{1, 64} {
		t.Run(fmt.Sprintf("%d records", count), func(t *testing.T) {
			values := make([]string, count)
			for index := range values {
				values[index] = fmt.Sprintf("record-%03d", index)
			}
			output, stop := startLegacyBrokerConsumer(t, map[int32][]string{0: values})
			for index, want := range values {
				// Yield between reads to exercise a slower unbuffered downstream.
				runtime.Gosched()
				if got := receiveLegacyMessage(t, output); got != want {
					t.Fatalf("record %d = %q, want %q", index, got, want)
				}
			}
			stop()
		})
	}
}

func TestLegacyConsumerBackpressureAndStop(t *testing.T) {
	for _, receiveFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("receive first %t", receiveFirst), func(t *testing.T) {
			input := make(chan *sarama.ConsumerMessage)
			output := make(chan []byte)
			childClosed := make(chan struct{})
			var closed atomic.Bool
			child := &legacyTestPartition{
				messages: input,
				errors:   make(chan *sarama.ConsumerError),
				close: func() error {
					closed.Store(true)
					close(childClosed)
					return nil
				},
			}
			master := &legacyTestMaster{
				partitions: func(string) ([]int32, error) { return []int32{0}, nil },
				consume: func(string, int32, int64) (sarama.PartitionConsumer, error) {
					return child, nil
				},
				close: func() error {
					if !closed.Load() {
						t.Error("master closed before partition consumer")
					}
					return nil
				},
			}
			k := &kafka{stopCh: make(chan struct{}), master: master, topics: []*TopicDescriptor{{
				TopicName: "blocked-consumer", TopicChan: output,
			}}}
			stop := startLegacyTestConsumer(t, k)
			select {
			case input <- &sarama.ConsumerMessage{Value: []byte("first")}:
			case <-time.After(legacyConsumerTestTimeout):
				t.Fatal("reader did not accept first record")
			}
			secondAccepted := make(chan struct{})
			feederDone := make(chan struct{})
			go func() {
				defer close(feederDone)
				select {
				case input <- &sarama.ConsumerMessage{Value: []byte("second")}:
					close(secondAccepted)
				case <-k.stopCh:
				}
			}()
			// With no downstream receiver, production must stop consuming inputs.
			// This fails deterministically for the old goroutine-per-message code,
			// even on a scheduler that happens to deliver its goroutines in order.
			select {
			case <-secondAccepted:
				t.Error("consumed a second record while downstream was blocked")
			case <-time.After(50 * time.Millisecond):
			}
			if receiveFirst {
				if got := receiveLegacyMessage(t, output); got != "first" {
					t.Errorf("first output = %q, want first", got)
				}
				awaitLegacySignal(t, secondAccepted, "second input after downstream progressed")
			}
			stop()
			awaitLegacySignal(t, feederDone, "input feeder shutdown")
			select {
			case <-childClosed:
			default:
				t.Error("Stop returned before partition consumer closed")
			}
			// Stop is cancellation, not a promise to drain the stalled downstream.
			// There must be no orphan send that becomes deliverable after it returns.
			select {
			case value := <-output:
				t.Errorf("received %q after Stop returned", value)
				// Release a possible second old-code send in the negative control.
				select {
				case <-output:
				case <-time.After(10 * time.Millisecond):
				}
			default:
			}
		})
	}
}

func TestLegacyConsumerClosedChannels(t *testing.T) {
	for _, closeErrorsFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("errors close first %t", closeErrorsFirst), func(t *testing.T) {
			input := make(chan *sarama.ConsumerMessage)
			consumerErrors := make(chan *sarama.ConsumerError)
			childClosed := make(chan struct{})
			output := make(chan []byte)
			var calls atomic.Int32
			child := &legacyTestPartition{
				messages: input,
				errors:   consumerErrors,
				close:    func() error { close(childClosed); return nil },
			}
			master := &legacyTestMaster{
				partitions: func(string) ([]int32, error) { return []int32{0}, nil },
				consume: func(string, int32, int64) (sarama.PartitionConsumer, error) {
					calls.Add(1)
					return child, nil
				},
				close: func() error { return nil },
			}
			k := &kafka{stopCh: make(chan struct{}), master: master, topics: []*TopicDescriptor{{
				TopicName: "closed-channels", TopicChan: output,
			}}}
			stop := startLegacyTestConsumer(t, k)
			for _, consumerError := range []*sarama.ConsumerError{nil, {
				Topic: "closed-channels", Partition: 4, Err: sarama.ErrNotLeaderForPartition,
			}} {
				select {
				case consumerErrors <- consumerError:
				case <-time.After(legacyConsumerTestTimeout):
					t.Fatal("reader did not accept consumer error")
				}
			}
			if closeErrorsFirst {
				close(consumerErrors)
			}
			send := func(message *sarama.ConsumerMessage) {
				t.Helper()
				select {
				case input <- message:
				case <-time.After(legacyConsumerTestTimeout):
					t.Fatal("reader stopped before message channel closed")
				}
			}
			send(nil) // Nil entries must still be ignored.
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				select {
				case input <- &sarama.ConsumerMessage{Value: []byte("after-error-close")}:
				case <-k.stopCh:
				}
			}()
			if got := receiveLegacyMessage(t, output); got != "after-error-close" {
				t.Errorf("message = %q", got)
			}
			awaitLegacySignal(t, sent, "message sender")
			close(input)
			// A closed Messages channel ends the reader even while Errors is open.
			awaitLegacySignal(t, childClosed, "reader exit on closed Messages")
			if !closeErrorsFirst {
				close(consumerErrors)
			}
			stop()
			if got := calls.Load(); got != 1 {
				t.Errorf("ConsumePartition calls = %d, want 1 (no replay from oldest)", got)
			}
		})
	}
}
