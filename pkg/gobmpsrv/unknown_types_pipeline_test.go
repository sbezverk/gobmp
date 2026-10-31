package gobmpsrv

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"testing/synctest"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

func TestBMPWorkerUnknownTypesContinueStream(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, kind := range []byte{7, 127, 255} {
			for _, body := range [][]byte{nil, {1, 2, 3}} {
				t.Run(fmt.Sprintf("raw=%t/type=%d/payload=%d", raw, kind, len(body)), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						pub := &pipelineOrderPublisher{messages: make(chan orderedPublication, 2)}
						server, client := net.Pipe()
						done := workerDone(&bmpServer{publisher: pub, bmpRaw: raw}, wrapAddr(server, "192.0.2.1:5000"))
						defer func() { _ = client.Close(); <-done }()
						unknown := append([]byte{3, 0, 0, 0, 0, kind}, body...)
						binary.BigEndian.PutUint32(unknown[1:5], uint32(len(unknown)))
						valid := makePeerDownMessage()
						wire := append(append([]byte(nil), unknown...), valid...)
						if n, err := client.Write(wire); n != len(wire) || err != nil {
							t.Fatalf("write=%d/%d err=%v; unknown type must not disconnect", n, len(wire), err)
						}
						_ = client.Close()
						<-done
						want := 1
						if raw {
							want = 2
						}
						if got := len(pub.messages); got != want {
							t.Fatalf("publications=%d, want %d", got, want)
						}
						if !raw {
							if record := <-pub.messages; record.kind != bmp.PeerStateChangeMsg {
								t.Fatalf("parsed publication type=%d, want PeerDown", record.kind)
							}
							return
						}
						for i, frame := range [][]byte{unknown, valid} {
							record := <-pub.messages
							if record.kind != bmp.BMPRawMsg || len(record.data) < 8 {
								t.Fatalf("publication %d is not an OpenBMP RAW record", i)
							}
							headerLen := int(binary.BigEndian.Uint16(record.data[6:8]))
							if headerLen > len(record.data) || !bytes.Equal(record.data[headerLen:], frame) {
								t.Fatalf("RAW publication %d does not preserve the corresponding BMP frame", i)
							}
						}
					})
				})
			}
		}
	}
}

func TestBMPWorkerEmptyKnownPeerTypesStillRejected(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, kind := range []byte{bmp.RouteMonitorMsg, bmp.StatsReportMsg, bmp.PeerDownMsg, bmp.PeerUpMsg, bmp.RouteMirrorMsg} {
			t.Run(fmt.Sprintf("raw=%t/type=%d", raw, kind), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					pub := &pipelineOrderPublisher{messages: make(chan orderedPublication, 2)}
					server, client := net.Pipe()
					done := workerDone(&bmpServer{publisher: pub, bmpRaw: raw}, wrapAddr(server, "192.0.2.1:5000"))
					defer func() { _ = client.Close(); <-done }()
					header := []byte{3, 0, 0, 0, 6, kind}
					if n, err := client.Write(append(header, makePeerDownMessage()...)); n != len(header) || err == nil {
						t.Errorf("write=%d err=%v, want empty known frame rejected before the next frame", n, err)
					}
					<-done
					if got := len(pub.messages); got != 0 {
						t.Errorf("published %d records after invalid empty known frame", got)
					}
				})
			})
		}
	}
}

func TestBMPWorkerOversizedUnknownTypeStillRejected(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(fmt.Sprintf("raw=%t", raw), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pub := &pipelineOrderPublisher{messages: make(chan orderedPublication, 1)}
				server, client := net.Pipe()
				done := workerDone(&bmpServer{publisher: pub, bmpRaw: raw}, wrapAddr(server, "192.0.2.1:5000"))
				defer func() { _ = client.Close(); <-done }()
				header := []byte{3, 0, 0, 0, 0, 255}
				binary.BigEndian.PutUint32(header[1:5], uint32(bmp.CommonHeaderLength+maxBMPMessagePayload+1))
				if n, err := client.Write(header); n != len(header) || err != nil {
					t.Fatalf("write header=%d err=%v", n, err)
				}
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("oversized unknown frame was not rejected before payload read")
				}
				if got := len(pub.messages); got != 0 {
					t.Errorf("oversized unknown frame published %d records", got)
				}
			})
		})
	}
}
