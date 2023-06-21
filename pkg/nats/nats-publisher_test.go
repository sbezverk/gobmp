package nats

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	natssrv "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/gobmpsrv"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/pub"
	"gotest.tools/assert"
)

const (
	streamName = "gobmp"
	natsPrefix = "gobmp"
	bmpPort    = 5000
)

var (
	p pub.Publisher
	s nats.JetStreamContext
	b gobmpsrv.BMPServer
)

func TestMain(m *testing.M) {
	// build in-memory NATS server
	natsSrv, err := natssrv.NewServer(&natssrv.Options{
		Host:      "127.0.0.1",
		Debug:     false,
		Port:      natssrv.RANDOM_PORT,
		JetStream: true,
	})
	if err != nil {
		panic(err)
	}

	defer natsSrv.Shutdown()

	// Start NATS server
	if err := natssrv.Run(natsSrv); err != nil {
		panic(err)
	}

	// Create a NATS connection for subscribing
	nc, err := nats.Connect(natsSrv.ClientURL())
	if err != nil {
		panic(err)
	}
	defer nc.Close()

	s, err = nc.JetStream()
	if err != nil {
		panic(err)
	}

	// Create the stream
	_, err = s.AddStream(&nats.StreamConfig{
		Name:     streamName,
		Subjects: []string{streamName + ".>"},
	})
	if err != nil {
		panic(err)
	}

	// Create the Publisher
	p, err = NewPublisher(natsSrv.ClientURL())
	if err != nil {
		panic(err)
	}

	// Start BMP
	b, err = gobmpsrv.NewBMPServer(bmpPort, 0, false, p, false, "")
	if err != nil {
		panic(err)
	}

	// Starting Interceptor server
	b.Start()

	m.Run()
}

// TestNATSProducer tests NATS producer
func TestNATSProducer(t *testing.T) {
	input := []byte{3, 0, 0, 0, 32, 4, 0, 1, 0, 10, 32, 55, 46, 50, 46, 49, 46, 50, 51, 73, 0, 2, 0, 8, 120, 114, 118, 57, 107, 45, 114, 49, 3, 0, 0, 0, 234, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 103, 0, 0, 19, 206, 57, 112, 1, 254, 94, 98, 129, 171, 0, 0, 215, 126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 80, 128, 0, 179, 131, 152, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 91, 1, 4, 19, 206, 0, 90, 192, 168, 8, 8, 62, 2, 6, 1, 4, 0, 1, 0, 1, 2, 6, 1, 4, 0, 1, 0, 4, 2, 6, 1, 4, 0, 1, 0, 128, 2, 2, 128, 0, 2, 2, 2, 0, 2, 6, 65, 4, 0, 0, 19, 206, 2, 20, 5, 18, 0, 1, 0, 1, 0, 2, 0, 1, 0, 2, 0, 2, 0, 1, 0, 128, 0, 2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 75, 1, 4, 19, 206, 0, 90, 57, 112, 1, 254, 46, 2, 44, 2, 0, 1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1, 1, 4, 0, 1, 0, 4, 1, 4, 0, 2, 0, 4, 1, 4, 0, 1, 0, 128, 1, 4, 0, 2, 0, 128, 65, 4, 0, 0, 19, 206}

	// Create a connection to the BMP server
	conn, err := net.Dial("tcp", fmt.Sprintf(":%d", bmpPort))
	if err != nil {
		t.Fatalf("failed to connect to gobmp server with error: %+v", err)
	}
	defer conn.Close()

	// Send message to the BMP server
	_, err = conn.Write(input)
	if err != nil {
		t.Fatalf("failed to send message to gobmp server with error: %+v", err)
	}

	// Wait for message to be published
	sub, err := s.SubscribeSync(streamName + ".>")
	if err != nil {
		t.Fatalf("failed to subscribe to stream with error: %+v", err)
	}

	// Wait to receive the message from the publisher
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("failed to pull message from stream with error: %+v", err)
	}

	// Unmarshal msg.Data (bytes) to message.PeerStateChange
	var peerStateChange message.PeerStateChange
	err = json.Unmarshal(msg.Data, &peerStateChange)
	if err != nil {
		t.Fatalf("failed to unmarshal message with error: %+v", err)
	}

	assert.Equal(t, peerStateChange.Action, "add")
	assert.Equal(t, peerStateChange.RouterHash, "4371c52d8d4a6a67a4c438964f61700b")
}
