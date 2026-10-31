package kafka

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// MockBroker records History before writing the response. Gate the actual
// connection write so a received ProduceRequest cannot be mistaken for an ACK.
type produceAckGate struct {
	broker      *sarama.MockBroker
	armed       atomic.Bool
	pending     chan struct{}
	release     chan struct{}
	pendingOnce sync.Once
	releaseOnce sync.Once
}

func (g *produceAckGate) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }

type ackGateListener struct {
	net.Listener
	gate *produceAckGate
}

func (l *ackGateListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ackGateConn{Conn: conn, gate: l.gate}, nil
}

type ackGateConn struct {
	net.Conn
	gate *produceAckGate
}

func (c *ackGateConn) Write(b []byte) (int, error) {
	if c.gate.armed.Load() {
		history := c.gate.broker.History()
		if len(history) != 0 {
			if _, ok := history[len(history)-1].Request.(*sarama.ProduceRequest); ok {
				c.gate.pendingOnce.Do(func() { close(c.gate.pending) })
				<-c.gate.release
			}
		}
	}
	return c.Conn.Write(b)
}

func newShutdownBroker(t *testing.T, produceError sarama.KError) *produceAckGate {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := &produceAckGate{pending: make(chan struct{}), release: make(chan struct{})}
	gate.broker = sarama.NewMockBrokerListener(t, 1, &ackGateListener{Listener: listener, gate: gate})
	gate.broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(gate.broker.Addr(), gate.broker.BrokerID()).
			SetLeader(PeerTopic, 0, gate.broker.BrokerID()),
		"ProduceRequest": sarama.NewMockProduceResponse(t).SetError(PeerTopic, 0, produceError),
	})
	t.Cleanup(gate.broker.Close)
	t.Cleanup(gate.unblock)
	return gate
}

func newShutdownPublisher(t *testing.T, produceError sarama.KError) (*publisher, *produceAckGate, func()) {
	t.Helper()
	gate := newShutdownBroker(t, produceError)
	pub, err := NewKafkaPublisher(&Config{
		ServerAddress: gate.broker.Addr(), TopicRetentionTimeMs: "900000", SkipTopicCreation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := pub.(*publisher)
	stop := sync.OnceFunc(p.Stop) // Keep test cleanup from stopping an instance twice.
	t.Cleanup(func() { gate.unblock(); stop() })
	gate.armed.Store(true)
	return p, gate, stop
}

type shutdownAdmin struct {
	sarama.ClusterAdmin
	closed chan struct{}
	err    error
}

func (a *shutdownAdmin) Close() error {
	close(a.closed)
	return a.err
}

func TestStopWaitsForProduceACK(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome sarama.KError
	}{{"success", sarama.ErrNoError}, {"terminal delivery error", sarama.ErrMessageSizeTooLarge}} {
		t.Run(tc.name, func(t *testing.T) {
			p, gate, stop := newShutdownPublisher(t, tc.outcome)
			admin := &shutdownAdmin{closed: make(chan struct{})}
			p.clusterAdmin = admin
			if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("peer"), []byte("tail")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-gate.pending:
			case <-time.After(5 * time.Second):
				t.Fatal("broker did not reach the blocked Produce response")
			}
			stopped := make(chan struct{})
			go func() { stop(); close(stopped) }()
			select {
			case <-stopped:
				t.Fatal("Stop returned before the broker could write its response")
			case <-admin.closed:
				t.Fatal("admin closed before the producer's pending response")
			case <-time.After(50 * time.Millisecond):
			}
			gate.unblock()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("Stop did not finish after the Produce response")
			}
			select {
			case <-admin.closed:
			default:
				t.Fatal("Stop did not close the admin client")
			}
			if _, open := <-p.producer.Errors(); open {
				t.Fatal("producer error channel remains open after Stop")
			}
			if _, open := <-p.producer.Successes(); open {
				t.Fatal("producer success channel remains open after Stop")
			}
		})
	}
}

func TestStopDrainsConcurrentPublishers(t *testing.T) {
	p, gate, stop := newShutdownPublisher(t, sarama.ErrNoError)
	gate.unblock()
	var senders sync.WaitGroup
	for i := 0; i < 16; i++ {
		senders.Add(1)
		go func() {
			defer senders.Done()
			if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("peer"), []byte("tail")); err != nil {
				t.Error(err)
			}
		}()
	}
	senders.Wait()
	stop()
	if _, open := <-p.producer.Errors(); open {
		t.Fatal("producer remains open after publishing workers finish and Stop returns")
	}
}

func TestStopCompletesOnUnansweredProduce(t *testing.T) {
	originalTimeout := netReadTimeout
	netReadTimeout = 200 * time.Millisecond
	defer func() { netReadTimeout = originalTimeout }()
	p, gate, stop := newShutdownPublisher(t, sarama.ErrNoError)
	gate.unblock()
	gate.broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(gate.broker.Addr(), gate.broker.BrokerID()).
			SetLeader(PeerTopic, 0, gate.broker.BrokerID()),
		// Missing ProduceRequest response exercises Sarama's existing finite
		// produce retries without turning shutdown into a successful delivery.
	})
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("peer"), []byte("tail")); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not finish after the bounded test broker retries")
	}
	if _, open := <-p.producer.Errors(); open {
		t.Fatal("producer remains open after its terminal delivery error")
	}
}

const stopReturnedMarker = "KAFKA_STOP_RETURNED"

type stopMarkerWriter struct {
	buffer   bytes.Buffer
	returned chan struct{}
	once     sync.Once
}

func (w *stopMarkerWriter) Write(b []byte) (int, error) {
	n, err := w.buffer.Write(b)
	if bytes.Contains(w.buffer.Bytes(), []byte(stopReturnedMarker)) {
		w.once.Do(func() { close(w.returned) })
	}
	return n, err
}

func TestKafkaShutdownSubprocess(t *testing.T) {
	for _, failDelivery := range []bool{false, true} {
		t.Run(fmt.Sprintf("delivery_error_%t", failDelivery), func(t *testing.T) {
			outcome := sarama.ErrNoError
			if failDelivery {
				outcome = sarama.ErrMessageSizeTooLarge
			}
			gate := newShutdownBroker(t, outcome)
			gate.armed.Store(true)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKafkaShutdownChild$", "-logtostderr=true")
			cmd.Env = append(os.Environ(), "GOBMP_SHUTDOWN_TEST_BROKER="+gate.broker.Addr(), fmt.Sprintf("GOBMP_SHUTDOWN_TEST_ERROR=%t", failDelivery))
			stdout := &stopMarkerWriter{returned: make(chan struct{})}
			var stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			waitDone := make(chan struct{})
			go func() {
				defer close(waitDone)
				exited <- cmd.Wait()
			}()
			t.Cleanup(func() { gate.unblock(); cancel(); <-waitDone })
			select {
			case <-gate.pending:
			case <-stdout.returned:
				t.Fatal("child Stop returned before an acknowledged tail message")
			case err := <-exited:
				t.Fatalf("child exited before reaching the delayed ACK: %v; %s", err, stderr.String())
			case <-ctx.Done():
				t.Fatal("child did not reach the delayed ACK")
			}
			select {
			case <-stdout.returned:
				t.Fatal("child Stop returned while the broker's response was withheld")
			case err := <-exited:
				t.Fatalf("child exited while its ACK was withheld: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			gate.unblock()
			select {
			case err := <-exited:
				if err != nil {
					t.Fatalf("child failed: %v; %s", err, stderr.String())
				}
			case <-ctx.Done():
				t.Fatal("child did not exit after receiving its Produce response")
			}
			select {
			case <-stdout.returned:
			default:
				t.Fatalf("child exited without confirming Stop completion: %s", stdout.buffer.String())
			}
			produceRequests := 0
			for _, exchange := range gate.broker.History() {
				if _, ok := exchange.Request.(*sarama.ProduceRequest); ok {
					produceRequests++
				}
			}
			if produceRequests != 1 {
				t.Fatalf("tail Produce requests = %d, want 1", produceRequests)
			}
			if failDelivery {
				if !strings.Contains(stderr.String(), "failed to close Kafka cluster admin: test admin close failure") {
					t.Fatalf("admin Close error was not logged: %s", stderr.String())
				}
				if !strings.Contains(stderr.String(), "failed to close Kafka producer") && !strings.Contains(stderr.String(), "failed to produce message") {
					t.Fatalf("delivery failure was not logged: %s", stderr.String())
				}
			}
		})
	}
}

func TestKafkaShutdownChild(t *testing.T) {
	address := os.Getenv("GOBMP_SHUTDOWN_TEST_BROKER")
	if address == "" {
		t.Skip("subprocess helper")
	}
	pub, err := NewKafkaPublisher(&Config{ServerAddress: address, TopicRetentionTimeMs: "900000", SkipTopicCreation: true})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("GOBMP_SHUTDOWN_TEST_ERROR") == "true" {
		pub.(*publisher).clusterAdmin = &shutdownAdmin{closed: make(chan struct{}), err: errors.New("test admin close failure")}
	}
	if err := pub.PublishMessage(bmp.PeerStateChangeMsg, []byte("peer"), []byte("tail")); err != nil {
		t.Fatal(err)
	}
	pub.Stop()
	if _, err := fmt.Fprintln(os.Stdout, stopReturnedMarker); err != nil {
		t.Fatal(err)
	}
}
