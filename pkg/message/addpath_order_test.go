package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

type addPathOrderedPublisher struct {
	recordingPublisher
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *addPathOrderedPublisher) PublishMessage(kind int, hash, payload []byte) error {
	if kind == bmp.UnicastPrefixMsg {
		p.once.Do(func() {
			close(p.entered)
			<-p.release
		})
	}
	return p.recordingPublisher.PublishMessage(kind, hash, payload)
}

func addPathOrderedUpdate(t *testing.T, mp, enabled bool) *bmp.RouteMonitor {
	t.Helper()
	announce, withdraw := []byte{24, 192, 0, 2}, []byte{24, 198, 51, 100}
	if enabled {
		announce = append([]byte{0, 0, 1, 0}, announce...)
		withdraw = append([]byte{0, 0, 1, 0}, withdraw...)
	}
	var wire []byte
	if mp {
		reach := append([]byte{0, 1, 1, 4, 192, 0, 2, 1, 0}, announce...)
		unreach := append([]byte{0, 1, 1}, withdraw...)
		attrs := append([]byte{0x80, bgp.MP_REACH_NLRI, byte(len(reach))}, reach...)
		attrs = append(attrs, 0x80, bgp.MP_UNREACH_NLRI, byte(len(unreach)))
		attrs = append(attrs, unreach...)
		wire = make([]byte, 4)
		binary.BigEndian.PutUint16(wire[2:], uint16(len(attrs)))
		wire = append(wire, attrs...)
	} else {
		wire = append([]byte{0, byte(len(withdraw))}, withdraw...)
		wire = append(wire, 0, 0)
		wire = append(wire, announce...)
	}
	update, err := bgp.UnmarshalBGPUpdate(wire)
	if err != nil {
		t.Fatal(err)
	}
	return &bmp.RouteMonitor{Update: update}
}

func TestProducerAddPathStateOrder(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	views := []struct {
		name       string
		peerType   bmp.PeerType
		flags      byte
		localMode  uint8
		remoteMode uint8
	}{
		{"in", bmp.PeerType0, 0, 1, 2},
		{"out", bmp.PeerType0, 0x10, 2, 1},
		{"loc-rib", bmp.PeerType3, 0, 1, 1},
	}
	for _, view := range views {
		for _, encoding := range []string{"legacy", "mp"} {
			for _, transition := range []string{"down", "replacement"} {
				t.Run(view.name+"/"+encoding+"/"+transition, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						pub := &addPathOrderedPublisher{entered: make(chan struct{}), release: make(chan struct{})}
						p := NewProducer(pub, false).(*producer)
						queue, stop := make(chan bmp.Message), make(chan struct{})
						go p.Producer(queue, stop)
						released := false
						defer func() {
							if !released {
								close(pub.release)
							}
							close(stop)
							synctest.Wait()
						}()

						ph := makePeerHeader(t, view.peerType, view.flags)
						up := buildPeerUpMessage(t, "192.0.2.1")
						up.SentOpen = addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: view.localMode})
						up.ReceivedOpen = addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: view.remoteMode})
						up.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}}
						queue <- bmp.Message{PeerHeader: ph, Payload: up}
						// The first data message follows PeerUp immediately, with no worker barrier.
						queue <- bmp.Message{PeerHeader: ph, Payload: addPathOrderedUpdate(t, encoding == "mp", true)}
						synctest.Wait()
						select {
						case <-pub.entered:
						default:
							t.Fatal("first ADD-PATH route did not reach the publisher")
						}

						next := bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 4}}
						if transition == "replacement" {
							plain := buildPeerUpMessage(t, "192.0.2.1")
							plain.SentOpen = addPathOpen(t, []bgp.AFISAFI{family}, nil)
							plain.ReceivedOpen = plain.SentOpen
							plain.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-B")}}
							next.Payload = plain
						}
						accepted := make(chan struct{})
						go func() { queue <- next; close(accepted) }()
						synctest.Wait()
						select {
						case <-accepted:
							t.Error("later peer transition overtook a blocked route publication")
						default:
						}
						if !p.addPathEnabled(ph, family) {
							t.Error("later peer transition changed the active route's ADD-PATH state")
						}
						if view.peerType == bmp.PeerType3 && p.getTableName(ph) != "VRF-A" {
							t.Error("later peer transition changed the active route's Loc-RIB table name")
						}

						close(pub.release)
						released = true
						synctest.Wait()
						if p.addPathEnabled(ph, family) || p.addPathEnabled(makePeerHeader(t, view.peerType, view.flags^0x10), family) {
							t.Error("peer transition retained old ADD-PATH state")
						}
						wantActions := []string{"add", "del", "add", "down"}
						if encoding == "mp" {
							wantActions[1], wantActions[2] = "add", "del"
						}
						if transition == "replacement" {
							wantActions[3] = "add"
							queue <- bmp.Message{PeerHeader: ph, Payload: addPathOrderedUpdate(t, encoding == "mp", false)}
							synctest.Wait()
							queue <- bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 4}}
							synctest.Wait()
							wantActions = append(wantActions, wantActions[1], wantActions[2], "down")
						}
						if view.peerType == bmp.PeerType3 && p.getTableName(ph) != "" {
							t.Error("PeerDown retained the Loc-RIB table name")
						}
						if len(pub.msgs) != len(wantActions) {
							t.Fatalf("published messages = %d, want %d", len(pub.msgs), len(wantActions))
						}
						for i, recorded := range pub.msgs {
							if i == 0 || i == 3 || i == 6 {
								var peer PeerStateChange
								if err := json.Unmarshal(recorded.payload, &peer); err != nil {
									t.Fatal(err)
								}
								if recorded.msgType != bmp.PeerStateChangeMsg || peer.Action != wantActions[i] {
									t.Errorf("message %d = type %d action %q, want peer %q", i, recorded.msgType, peer.Action, wantActions[i])
								}
								continue
							}
							var route UnicastPrefix
							if err := json.Unmarshal(recorded.payload, &route); err != nil {
								t.Fatal(err)
							}
							wantPath := int32(256)
							wantTable := ""
							if view.peerType == bmp.PeerType3 {
								wantTable = "VRF-A"
							}
							if i > 3 {
								wantPath = 0
								if wantTable != "" {
									wantTable = "VRF-B"
								}
							}
							wantPrefix := "192.0.2.0"
							if wantActions[i] == "del" {
								wantPrefix = "198.51.100.0"
							}
							if recorded.msgType != bmp.UnicastPrefixMsg || route.Action != wantActions[i] || route.PathID != wantPath || route.Prefix != wantPrefix || route.PrefixLen != 24 {
								t.Errorf("message %d = type %d route %+v, want %s %s/24 PathID %d", i, recorded.msgType, route, wantActions[i], wantPrefix, wantPath)
							}
							if route.IsAdjRIBOut != (view.flags == 0x10) || route.IsLocRIB != (view.peerType == bmp.PeerType3) || route.TableName != wantTable {
								t.Errorf("message %d has wrong monitored view/table: %+v", i, route)
							}
						}
					})
				})
			}
		}
	}
}

func TestProducerAddPathReadiness(t *testing.T) {
	family := bgp.AFISAFI{AFI: 1, SAFI: 1}
	for _, peerType := range []bmp.PeerType{bmp.PeerType0, bmp.PeerType3} {
		t.Run(fmt.Sprintf("peer-type-%d", peerType), func(t *testing.T) {
			p := NewProducer(&recordingPublisher{}, false).(*producer)
			ph := makePeerHeader(t, peerType, 0)
			up := buildPeerUpMessage(t, "192.0.2.1")
			up.SentOpen = addPathOpen(t, []bgp.AFISAFI{family}, map[bgp.AFISAFI]uint8{family: 3})
			up.ReceivedOpen = up.SentOpen
			up.Information = []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-A")}}
			p.tableLock.Lock()
			locked := true
			done := make(chan struct{})
			go func() {
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: up})
				close(done)
			}()
			defer func() {
				if locked {
					p.tableLock.Unlock()
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("PeerUp did not complete after releasing property installation")
				}
			}()

			// Mutex waits are not synctest-durable. Observe the actual parked
			// installer rather than assuming a sleep gave it enough time to run.
			deadline := time.Now().Add(5 * time.Second)
			stacks := make([]byte, 1<<20)
			for {
				n := runtime.Stack(stacks, true)
				parked := false
				for _, stack := range bytes.Split(stacks[:n], []byte("\n\n")) {
					if bytes.Contains(stack, []byte("(*producer).setPeerProperties(")) && bytes.Contains(stack, []byte("sync.(*RWMutex).Lock(")) {
						parked = true
						break
					}
				}
				if parked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("PeerUp did not park at property installation:\n%s", stacks[:n])
				}
				runtime.Gosched()
			}
			select {
			case <-p.speakerReady:
				t.Error("speakerReady closed before ADD-PATH/table properties were installed")
			default:
			}
			p.tableLock.Unlock()
			locked = false
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("PeerUp did not complete property installation")
			}
			assertSpeakerReady(t, p)
			if !p.addPathEnabled(ph, family) || (peerType == bmp.PeerType3 && p.getTableName(ph) != "VRF-A") {
				t.Fatal("ready PeerUp is missing its ADD-PATH/table properties")
			}
		})
	}
}
