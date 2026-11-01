package kafka

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

type gatedShutdownAdmin struct {
	sarama.ClusterAdmin
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (a *gatedShutdownAdmin) Close() error {
	a.calls.Add(1)
	select {
	case a.entered <- struct{}{}:
	default:
	}
	<-a.release
	return errors.New("controlled admin close failure")
}

func TestStopConcurrentCallersWaitForFullShutdown(t *testing.T) {
	const cohort = 16
	admin := &gatedShutdownAdmin{entered: make(chan struct{}, 2*cohort), release: make(chan struct{})}
	p := &publisher{stopCh: make(chan struct{}), doneCh: make(chan struct{}), clusterAdmin: admin}
	finishProducer := sync.OnceFunc(func() { close(p.doneCh) })
	finishAdmin := sync.OnceFunc(func() { close(admin.release) })
	started, returned := make(chan struct{}, 2*cohort), make(chan struct{}, 2*cohort)
	var callers sync.WaitGroup
	t.Cleanup(func() {
		finishProducer()
		finishAdmin()
		joined := make(chan struct{})
		go func() { callers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("Stop callers did not finish after cleanup released both gates")
		}
	})
	launch := func() {
		for range cohort {
			callers.Add(1)
			go func() {
				defer callers.Done()
				started <- struct{}{}
				p.Stop()
				returned <- struct{}{}
			}()
		}
		for range cohort {
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("Stop callers did not reach the start barrier")
			}
		}
	}
	launch()
	select {
	case <-p.stopCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not signal the producer")
	}
	select {
	case <-returned:
		t.Fatal("Stop returned before producer completion")
	case <-admin.entered:
		t.Fatal("admin closed before producer completion")
	case <-time.After(50 * time.Millisecond):
	}
	finishProducer()
	select {
	case <-admin.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not close the admin after producer completion")
	}
	launch() // New callers must also wait while admin Close is in progress.
	select {
	case <-returned:
		t.Fatal("Stop returned before admin Close completed")
	case <-time.After(50 * time.Millisecond):
	}
	if got := admin.calls.Load(); got != 1 {
		t.Fatalf("admin Close calls while blocked = %d, want 1", got)
	}
	finishAdmin()
	for range 2 * cohort {
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop caller did not return after full shutdown")
		}
	}
	p.Stop()
	p.Stop()
	if got := admin.calls.Load(); got != 1 {
		t.Errorf("admin Close calls after repeated Stop = %d, want 1", got)
	}
}

func TestStopRepeatableWithRealProducer(t *testing.T) {
	p, gate, _ := newShutdownPublisher(t, sarama.ErrNoError)
	admin := &shutdownAdmin{closed: make(chan struct{})}
	p.clusterAdmin = admin
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("peer"), []byte("tail")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.pending:
	case <-time.After(5 * time.Second):
		t.Fatal("broker did not reach the held Produce response")
	}
	const count = 16
	started, returned := make(chan struct{}, count), make(chan struct{}, count)
	var callers sync.WaitGroup
	t.Cleanup(func() {
		gate.unblock()
		joined := make(chan struct{})
		go func() { callers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("Stop callers did not finish after cleanup released the ACK")
		}
	})
	for range count {
		callers.Add(1)
		go func() {
			defer callers.Done()
			started <- struct{}{}
			p.Stop()
			returned <- struct{}{}
		}()
	}
	for range count {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop callers did not reach the start barrier")
		}
	}
	select {
	case <-returned:
		t.Fatal("Stop returned while the Produce response was held")
	case <-admin.closed:
		t.Fatal("admin closed while the Produce response was held")
	case <-time.After(50 * time.Millisecond):
	}
	gate.unblock()
	for range count {
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("Stop caller did not finish after the Produce response")
		}
	}
	p.Stop()
	p.Stop()
	select {
	case <-p.doneCh:
	default:
		t.Error("producer worker has not completed after Stop")
	}
	select {
	case <-admin.closed:
	default:
		t.Error("admin remains open after Stop")
	}
	select {
	case _, open := <-p.producer.Errors():
		if open {
			t.Error("producer errors remain open after Stop")
		}
	case <-time.After(5 * time.Second):
		t.Error("producer errors did not close after Stop")
	}
	select {
	case _, open := <-p.producer.Successes():
		if open {
			t.Error("producer successes remain open after Stop")
		}
	case <-time.After(5 * time.Second):
		t.Error("producer successes did not close after Stop")
	}
}
