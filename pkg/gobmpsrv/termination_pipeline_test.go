package gobmpsrv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/config"
)

func TestBMPWorkerTerminationClosesWithoutFIN(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pub := &pipelineOrderPublisher{messages: make(chan orderedPublication, 2)}
				server, client := net.Pipe()
				done := workerDone(&bmpServer{publisher: pub, bmpRaw: raw}, wrapAddr(server, "192.0.2.1:5000"))
				defer func() { _ = client.Close(); <-done }()
				if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				termination := orderBMPFrame(bmp.TerminationMsg, 0, []byte{0, 1, 0, 2, 0, 0})
				wire := append(append([]byte(nil), termination...), makePeerDownMessage()...)
				n, err := client.Write(wire)
				if n != len(termination) || !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("write=%d/%d err=%v; want only Termination consumed and closed pipe", n, len(wire), err)
				}
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Errorf("peer read=%v, want EOF without peer FIN", err)
				}
				_ = client.Close()
				<-done
				want := 0
				if raw {
					want = 1
				}
				if got := len(pub.messages); got != want {
					t.Fatalf("published=%d, want %d; post-Termination frames must not publish", got, want)
				}
				if raw {
					record := <-pub.messages
					if record.kind != bmp.BMPRawMsg || len(record.data) < 8 {
						t.Fatal("expected an OpenBMP RAW record")
					}
					headerLen := int(binary.BigEndian.Uint16(record.data[6:8]))
					if headerLen > len(record.data) || !bytes.Equal(record.data[headerLen:], termination) {
						t.Fatal("RAW output did not preserve the Termination frame")
					}
				}
			})
		})
	}
}

func TestBMPWorkerTerminationClosesBeforePublicationDrain(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pub := &drainPublisher{release: make(chan struct{}), stoppedAt: -1}
				var release sync.Once
				unblock := func() { release.Do(func() { close(pub.release) }) }
				server, client := net.Pipe()
				srv := &bmpServer{publisher: pub, bmpRaw: raw, incoming: newMockListener(), clients: make(map[net.Conn]struct{}), connSem: make(chan struct{}, 1)}
				srv.connSem <- struct{}{}
				srv.startWorker(wrapAddr(server, "192.0.2.1:5000"), true)
				workerDone := make(chan struct{})
				go func() { srv.wg.Wait(); close(workerDone) }()
				defer func() { unblock(); _ = client.Close(); <-workerDone }()
				frames := [][]byte{
					orderBMPFrame(bmp.PeerDownMsg, 1, []byte{4}),
					orderBMPFrame(bmp.PeerDownMsg, 2, []byte{4}),
					orderBMPFrame(bmp.PeerDownMsg, 3, []byte{4}),
				}
				if _, err := client.Write(bytes.Join(frames, nil)); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				termination := orderBMPFrame(bmp.TerminationMsg, 0, []byte{0, 1, 0, 2, 0, 0})
				tail := orderBMPFrame(bmp.PeerDownMsg, 99, []byte{4})
				n, err := client.Write(append(append([]byte(nil), termination...), tail...))
				if n != len(termination) || !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("write=%d err=%v, want Termination followed by closed transport", n, err)
				}
				if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Errorf("peer read=%v, want EOF while publication is blocked", err)
				}
				stopped := make(chan struct{})
				go func() { srv.Stop(); close(stopped) }()
				synctest.Wait()
				select {
				case <-stopped:
					t.Error("Stop returned before accepted publications drained")
				default:
				}
				pub.mu.Lock()
				if pub.started != 3 || len(pub.messages) != 2 || pub.stoppedAt != -1 {
					t.Errorf("before drain: started=%d completed=%d stoppedAt=%d, want 3/2/-1", pub.started, len(pub.messages), pub.stoppedAt)
				}
				pub.mu.Unlock()
				unblock()
				synctest.Wait()
				<-workerDone
				<-stopped
				if got := len(srv.connSem); got != 0 {
					t.Errorf("connection slots retained=%d", got)
				}
				pub.mu.Lock()
				defer pub.mu.Unlock()
				want := 3
				if raw {
					want++
					frames = append(frames, termination)
				}
				if len(pub.messages) != want || pub.stoppedAt != want {
					t.Fatalf("completed=%d stoppedAt=%d, want %d accepted records", len(pub.messages), pub.stoppedAt, want)
				}
				for i, record := range pub.messages {
					if raw {
						if record.kind != bmp.BMPRawMsg || len(record.data) < 8 {
							t.Fatalf("publication %d is not an OpenBMP RAW record", i)
						}
						headerLen := int(binary.BigEndian.Uint16(record.data[6:8]))
						if headerLen > len(record.data) || !bytes.Equal(record.data[headerLen:], frames[i]) {
							t.Fatalf("RAW publication %d does not preserve accepted frame order", i)
						}
					} else {
						var event struct{ Timestamp string }
						if err := json.Unmarshal(record.data, &event); err != nil {
							t.Fatal(err)
						}
						if record.kind != bmp.PeerStateChangeMsg || event.Timestamp != fmt.Sprintf("1970-01-01T00:00:0%dZ", i+1) {
							t.Fatalf("parsed publication %d has wrong timestamp: %s", i, record.data)
						}
					}
				}
			})
		})
	}
}

func TestBMPServerActiveReconnectsAfterTermination(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			pub := newMockPublisher()
			srv, err := NewBMPServer(&config.Config{Publisher: pub, PublisherType: config.PublisherTypeKafka, KafkaConfig: &config.KafkaConfig{BmpRaw: raw}, ActiveMode: true, SpeakersList: []string{listener.Addr().String()}})
			if err != nil {
				t.Fatal(err)
			}
			srv.Start()
			defer stopWithTimeout(t, srv, 3*time.Second)
			first, err := acceptWithTimeout(listener, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = first.Close() }()
			if err := first.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := first.Write(orderBMPFrame(bmp.TerminationMsg, 0, []byte{0, 1, 0, 2, 0, 0})); err != nil {
				t.Fatal(err)
			}
			if _, err := first.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("sender read=%v, want collector EOF without sender FIN", err)
			}
			second, err := acceptWithTimeout(listener, 5*time.Second)
			if err != nil {
				t.Fatalf("active connector did not reconnect: %v", err)
			}
			defer func() { _ = second.Close() }()
			if raw && !pub.waitForMessages(1, time.Second) {
				t.Fatal("RAW Termination was not forwarded before reconnect")
			}
		})
	}
}
