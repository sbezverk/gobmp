package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"

	"github.com/google/nftables/binaryutil"

	"github.com/golang/glog"
)

var (
	dstPort int
	srcPort int
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
}

func server(incoming net.Listener, dstPort int, queue chan []byte) {
	glog.V(5).Infof("server running on port %d", srcPort)
	for {
		client, err := incoming.Accept()
		if err != nil {
			glog.Errorf("fail to accept client connection with error: %+v", err)
			continue
		}
		glog.V(5).Infof("client %+v accepted, calling the interceptor.", client.RemoteAddr())
		go interceptor(client, dstPort, queue)
	}
}

func interceptor(client net.Conn, dstPort int, queue chan []byte) {
	var err error
	defer client.Close()
	server, err := net.Dial("tcp", ":"+fmt.Sprintf("%d", dstPort))
	if err != nil {
		glog.Errorf("fail to connect to destination with error: %+v", err)
		return
	}
	defer server.Close()
	glog.V(5).Infof("connection to destination server %v established, start intercepting", server.RemoteAddr())
	b := make([]byte, 4096)
	var n int
	defer glog.V(5).Infof("all done with client %+v and server %+v error: %+v", client.RemoteAddr(), server.RemoteAddr(), err)
	for {
		n, err = client.Read(b)
		if err == io.EOF {
			break
		}
		if err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			continue
		}
		if n == 0 {
			continue
		}
		glog.V(5).Infof("read from client %+v %d bytes", client.RemoteAddr(), n)
		n, err = server.Write(b[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			glog.Errorf("fail to write to server %+v with error: %+v", server.RemoteAddr(), err)
			continue
		}
		glog.V(5).Infof("write to server %+v %d bytes", server.RemoteAddr(), n)
		// Never block main message loop
		go func(b []byte) {
			queue <- b
		}(b[:n])
		// Cleanning up
		b = b[:0]
	}
}

func parser(queue chan []byte, stop chan struct{}) {
	for {
		select {
		case b := <-queue:
			go parsingWorker(b)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
		}
	}
}

func parsingWorker(b []byte) {
	glog.V(6).Infof("parser received buffer: %+v length: %d", b, len(b))
	// Recovering common header first
	ch, err := unmarshalCommonHeader(b[0:7])
	if err != nil {
		glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
		return
	}
	glog.V(6).Infof("recovered common header, version: %d message length: %d message type: %d", ch.Version, ch.MessageLength, ch.MessageType)
	switch ch.MessageType {
	case 0:
		// *  Type = 0: Route Monitoring
	case 1:
		// *  Type = 1: Statistics Report
	case 2:
		// *  Type = 2: Peer Down Notification
	case 3:
		// *  Type = 3: Peer Up Notification
	case 4:
		// *  Type = 4: Initiation Message
		im, err := unmarshalInitiationMessage(b[7:ch.MessageLength])
		if err != nil {
			glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
			return
		}
		glog.V(6).Infof("recovered Initiation message %+v", *im)
	case 5:
		// *  Type = 5: Termination Message
	case 6:
		// *  Type = 6: Route Mirroring Message
	}
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	incoming, err := net.Listen("tcp", fmt.Sprintf(":%d", srcPort))
	if err != nil {
		glog.Errorf("fail to setup listener on port %d with error: %+v", err)
		os.Exit(1)
	}

	// Wait for the interrupt
	signals := make(chan os.Signal, 1)
	stop := make(chan bool)
	signal.Notify(signals, os.Interrupt)
	go func() {
		for range signals {
			glog.Infof("received interrupt, stopping.")
			stop <- true
		}
	}()

	queue := make(chan []byte)
	pstop := make(chan struct{})
	// Starting openBMP message parser
	go parser(queue, pstop)

	// Starting Interceptor server
	go server(incoming, dstPort, queue)

	<-stop
	os.Exit(0)
}

// BMPCommonHeader defines BMP message Common Header per rfc7854
type BMPCommonHeader struct {
	Version       byte
	MessageLength int32
	MessageType   byte
}

func unmarshalCommonHeader(b []byte) (*BMPCommonHeader, error) {
	ch := &BMPCommonHeader{}
	if b[0] != 3 {
		return nil, fmt.Errorf("invalid version in common header, expected 3 found %d", b[0])
	}
	ch.Version = b[0]
	ch.MessageLength = int32(binaryutil.BigEndian.Uint32(b[1:5]))
	ch.MessageType = b[5]
	// *  Type = 0: Route Monitoring
	// *  Type = 1: Statistics Report
	// *  Type = 2: Peer Down Notification
	// *  Type = 3: Peer Up Notification
	// *  Type = 4: Initiation Message
	// *  Type = 5: Termination Message
	// *  Type = 6: Route Mirroring Message
	switch ch.MessageType {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
	default:
		return nil, fmt.Errorf("invalid message type in common header, expected between 0 and 6 found %d", b[5])
	}

	return ch, nil
}

// BMPInformationalTLV defines Informational TLV per rfc7854
type BMPInformationalTLV struct {
	InformationType   int16
	InformationLength int16
	Information       []byte
}

// BMPInitiationMessage defines BMP Initiation Message per rfc7854
type BMPInitiationMessage struct {
	TLV []BMPInformationalTLV
}

func unmarshalInitiationMessage(b []byte) (*BMPInitiationMessage, error) {
	im := &BMPInitiationMessage{
		TLV: make([]BMPInformationalTLV, 0),
	}

	return im, nil
}
