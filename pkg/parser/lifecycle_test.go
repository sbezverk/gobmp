package parser

import (
	"testing"
	"testing/synctest"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestParserClosedInputDrainsWithoutClosingOutput(t *testing.T) {
	for _, count := range []int{0, 2} {
		synctest.Test(t, func(t *testing.T) {
			queue := make(chan []byte, count)
			output := make(chan bmp.Message, count+1)
			for range count {
				queue <- []byte{3, 0, 0, 0, 6, bmp.InitiationMsg}
			}
			close(queue)
			done := make(chan struct{})
			go func() { NewParser(queue, output, nil, &Config{EnableRawMode: true}).Start(); close(done) }()
			synctest.Wait()
			select {
			case <-done:
			default:
				t.Fatal("parser did not finish after draining closed input")
			}
			for range count {
				select {
				case msg := <-output:
					if _, ok := msg.Payload.(*bmp.RawMessage); !ok {
						t.Fatalf("payload=%T, want RAW frame", msg.Payload)
					}
				default:
					t.Fatal("parser lost a buffered input frame")
				}
			}
			// Sending to the still-open output proves it remains caller-owned.
			output <- bmp.Message{}
		})
	}
}

func TestParserExplicitStopInterruptsBlockedOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		queue := make(chan []byte, 1)
		queue <- []byte{3, 0, 0, 0, 6, bmp.InitiationMsg}
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			NewParser(queue, make(chan bmp.Message), stop, &Config{EnableRawMode: true}).Start()
			close(done)
		}()
		synctest.Wait()
		close(stop)
		synctest.Wait()
		<-done
	})
}
