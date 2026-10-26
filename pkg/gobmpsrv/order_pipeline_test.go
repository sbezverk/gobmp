package gobmpsrv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

type orderedPublication struct {
	kind int
	data []byte
}

type pipelineOrderPublisher struct{ messages chan orderedPublication }

func (p *pipelineOrderPublisher) PublishMessage(kind int, _, data []byte) error {
	p.messages <- orderedPublication{kind, append([]byte(nil), data...)}
	return nil
}
func (p *pipelineOrderPublisher) Stop() {}

func orderBMPFrame(kind byte, timestamp uint32, body []byte) []byte {
	frame := []byte{3, 0, 0, 0, 0, kind}
	if kind != bmp.InitiationMsg && kind != bmp.TerminationMsg {
		ph := make([]byte, bmp.PerPeerHeaderLength)
		copy(ph[22:26], []byte{192, 0, 2, 2})
		binary.BigEndian.PutUint32(ph[26:30], 65000)
		copy(ph[30:34], []byte{192, 0, 2, 2})
		binary.BigEndian.PutUint32(ph[34:38], timestamp)
		frame = append(frame, ph...)
	}
	frame = append(frame, body...)
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(frame)))
	return frame
}

func orderPeerUp() []byte {
	open := append(bytes.Repeat([]byte{0xff}, 16), 0, 29, 1, 4, 0xfd, 0xe8, 0, 90, 192, 0, 2, 1, 0)
	body := make([]byte, 20)
	copy(body[12:16], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(body[16:18], 179)
	binary.BigEndian.PutUint16(body[18:20], 179)
	body = append(body, open...)
	body = append(body, open...)
	return orderBMPFrame(bmp.PeerUpMsg, 1, body)
}

func orderUpdate(timestamp uint32, withdrawn, attrs, nlri []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	body = append(body, withdrawn...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(body, attrs...)
	body = append(body, nlri...)
	bgp := append(bytes.Repeat([]byte{0xff}, 16), 0, 0, 2)
	bgp = append(bgp, body...)
	binary.BigEndian.PutUint16(bgp[16:18], uint16(len(bgp)))
	return orderBMPFrame(bmp.RouteMonitorMsg, timestamp, bgp)
}

func orderFrames() [][]byte {
	prefixes := make([]byte, 0, 800*4)
	for i := 0; i < 800; i++ {
		prefixes = append(prefixes, 24, 10, byte(i/256), byte(i%256))
	}
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe8, 0x40, 3, 4, 192, 0, 2, 1}
	return [][]byte{
		orderBMPFrame(bmp.InitiationMsg, 0, nil),
		orderPeerUp(),
		orderUpdate(2, nil, attrs, prefixes), // 3243-byte BGP UPDATE, below the standard 4096-byte limit
		orderUpdate(3, []byte{24, 10, 3, 31}, nil, nil),
		orderUpdate(4, nil, nil, nil), // explicit IPv4 End-of-RIB
		orderBMPFrame(bmp.PeerDownMsg, 5, []byte{4}),
	}
}

func startOrderPipeline(t *testing.T, raw bool) (*pipelineOrderPublisher, net.Conn) {
	t.Helper()
	pub := &pipelineOrderPublisher{messages: make(chan orderedPublication, 2048)}
	server, client := net.Pipe()
	srv := &bmpServer{publisher: pub, bmpRaw: raw}
	done := workerDone(srv, wrapAddr(server, "192.0.2.1:5000"))
	t.Cleanup(func() { _ = client.Close(); assertWorkerExits(t, done) })
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return pub, client
}

func TestBMPWorkerPreservesRouteAndPeerOrder(t *testing.T) {
	pub, client := startOrderPipeline(t, false)
	if _, err := client.Write(bytes.Join(orderFrames(), nil)); err != nil {
		t.Fatal(err)
	}
	var order []string
	adds := 0
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case record := <-pub.messages:
			var event struct {
				Action    string `json:"action"`
				Prefix    string `json:"prefix"`
				Timestamp string `json:"timestamp"`
				IsEOR     bool   `json:"is_eor"`
			}
			if err := json.Unmarshal(record.data, &event); err != nil {
				t.Fatal(err)
			}
			switch record.kind {
			case bmp.PeerStateChangeMsg:
				order = append(order, "peer:"+event.Action)
				if event.Action == "down" {
					want := "peer:add,route:add,route:del,eor,peer:down"
					if got := strings.Join(order, ","); got != want || adds != 800 {
						t.Fatalf("publication order = %s, adds = %d; want %s and 800 adds", got, adds, want)
					}
					return
				}
			case bmp.UnicastPrefixMsg:
				if event.Action == "add" && !event.IsEOR {
					adds++
				}
				if event.Prefix == "10.3.31.0" {
					order = append(order, "route:"+event.Action)
				}
				// Identify the explicit EOR frame independently of any markers
				// emitted by processing the preceding withdrawal.
				if event.IsEOR && event.Timestamp == "1970-01-01T00:00:04Z" {
					order = append(order, "eor")
				}
			}
		case <-deadline.C:
			t.Fatalf("pipeline did not publish PeerDown; order so far: %v", order)
		}
	}
}

func TestBMPWorkerPreservesRawOrder(t *testing.T) {
	pub, client := startOrderPipeline(t, true)
	frames := orderFrames()
	// A large valid Initiation frame must not be overtaken by the shorter
	// peer and route frames while its OpenBMP envelope is being built.
	tlv := binary.BigEndian.AppendUint16([]byte{0, 0}, 60000)
	tlv = append(tlv, bytes.Repeat([]byte{'x'}, 60000)...)
	frames[0] = orderBMPFrame(bmp.InitiationMsg, 0, bytes.Repeat(tlv, 16))
	if _, err := client.Write(bytes.Join(frames, nil)); err != nil {
		t.Fatal(err)
	}
	for i, want := range frames {
		select {
		case record := <-pub.messages:
			if record.kind != bmp.BMPRawMsg || len(record.data) < 8 {
				t.Fatalf("RAW record %d: type %d, length %d", i, record.kind, len(record.data))
			}
			headerLen := int(binary.BigEndian.Uint16(record.data[6:8]))
			if headerLen > len(record.data) || !bytes.Equal(record.data[headerLen:], want) {
				t.Fatalf("RAW record %d does not contain the corresponding BMP frame", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("RAW frame %d was not published", i)
		}
	}
}
