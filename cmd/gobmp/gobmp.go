package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"

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
	// Loop through all found Common Headers in the slice and process them
	for i := 0; i < len(b); {
		// Recovering common header first
		ch, err := UnmarshalCommonHeader(b[i : i+6])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		glog.V(5).Infof("recovered common header, version: %d message length: %d message type: %d", ch.Version, ch.MessageLength, ch.MessageType)
		switch ch.MessageType {
		case 0:
			// *  Type = 0: Route Monitoring
			glog.V(5).Infof("found Route Monitoring")
		case 1:
			// *  Type = 1: Statistics Report
			glog.V(5).Infof("found Statistics Report")
		case 2:
			// *  Type = 2: Peer Down Notification
			glog.V(5).Infof("found Peer Down Notification message")
		case 3:
			// *  Type = 3: Peer Up Notification
			glog.V(5).Infof("found Peer Up Notification message")
		case 4:
			// *  Type = 4: Initiation Message
			glog.V(5).Infof("found Initiation message")
			_, err := UnmarshalInitiationMessage(b[i+6 : i+int(ch.MessageLength)])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case 5:
			// *  Type = 5: Termination Message
			glog.V(5).Infof("found Termination message")
		case 6:
			// *  Type = 6: Route Mirroring Message
			glog.V(5).Infof("found Route Mirroring message")
		}
		i += int(ch.MessageLength)
	}
}

func main() {
	flag.Parse()
	_ = flag.Set("logtostderr", "true")
	incoming, err := net.Listen("tcp", fmt.Sprintf(":%d", srcPort))
	if err != nil {
		glog.Errorf("fail to setup listener on port %d with error: %+v", srcPort, err)
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

func UnmarshalCommonHeader(b []byte) (*BMPCommonHeader, error) {
	ch := &BMPCommonHeader{}
	if b[0] != 3 {
		return nil, fmt.Errorf("invalid version in common header, expected 3 found %d", b[0])
	}
	ch.Version = b[0]
	ch.MessageLength = int32(binary.BigEndian.Uint32(b[1:5]))
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

func UnmarshalInitiationMessage(b []byte) (*BMPInitiationMessage, error) {
	im := &BMPInitiationMessage{
		TLV: make([]BMPInformationalTLV, 0),
	}
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		switch t {
		case 0:
		case 1:
		case 2:
		default:
			return nil, fmt.Errorf("invalid tlv type, expected between 0 and 2 found %d", t)
		}
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		v := b[i+4 : i+4+int(l)]
		im.TLV = append(im.TLV, BMPInformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return im, nil
}
