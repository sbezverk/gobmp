package kafka

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
)

func TestLegacyConsumerCloseErrorCleanup(t *testing.T) {
	closeError := errors.New("injected close failure")
	for _, test := range []struct {
		name        string
		childError  error
		parentError error
	}{
		{name: "success"},
		{name: "child error", childError: closeError},
		{name: "parent error", parentError: closeError},
		{name: "both errors", childError: closeError, parentError: closeError},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := make(chan *sarama.ConsumerMessage)
			output := make(chan []byte)
			childClosing := make(chan struct{})
			childClosed := make(chan struct{})
			releaseChild := make(chan struct{})
			parentClosed := make(chan struct{})
			var childCalls, parentCalls atomic.Int32
			child := &legacyTestPartition{
				messages: input,
				errors:   make(chan *sarama.ConsumerError),
				close: func() error {
					if childCalls.Add(1) == 1 {
						close(childClosing)
						<-releaseChild
						close(childClosed)
					}
					return test.childError
				},
			}
			master := &legacyTestMaster{
				partitions: func(string) ([]int32, error) { return []int32{0}, nil },
				consume: func(string, int32, int64) (sarama.PartitionConsumer, error) {
					return child, nil
				},
				close: func() error {
					select {
					case <-childClosed:
					default:
						t.Error("parent closed before partition cleanup completed")
					}
					if parentCalls.Add(1) == 1 {
						close(parentClosed)
					}
					return test.parentError
				},
			}
			k := &kafka{stopCh: make(chan struct{}), master: master, topics: []*TopicDescriptor{{
				TopicName: "close-errors", TopicChan: output,
			}}}
			// Always release the child, including when an earlier assertion fails.
			// The deadline also releases it if a broken reader never starts cleanup.
			released := make(chan struct{})
			go func() {
				defer close(released)
				select {
				case <-childClosing:
				case <-time.After(legacyConsumerTestTimeout):
				}
				close(releaseChild)
			}()
			t.Cleanup(func() { awaitLegacySignal(t, released, "cleanup releaser") })
			stop := startLegacyTestConsumer(t, k)
			select {
			case input <- &sarama.ConsumerMessage{Value: []byte("blocked")}:
			case <-time.After(legacyConsumerTestTimeout):
				t.Fatal("reader did not accept the record")
			}
			stop()
			awaitLegacySignal(t, released, "partition cleanup release")
			awaitLegacySignal(t, childClosed, "partition cleanup")
			awaitLegacySignal(t, parentClosed, "parent cleanup")
			if got := childCalls.Load(); got != 1 {
				t.Errorf("partition Close calls = %d, want 1", got)
			}
			if got := parentCalls.Load(); got != 1 {
				t.Errorf("parent Close calls = %d, want 1", got)
			}
			select {
			case value := <-output:
				t.Errorf("received %q after Stop returned", value)
			default:
			}
		})
	}
}
