package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

var (
	dstPort int
	srcPort int
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
}

func server(incoming net.Listener, dstPort int) {
	glog.V(5).Infof("server running on port %d", srcPort)
	for {
		client, err := incoming.Accept()
		if err != nil {
			glog.Errorf("fail to accept client connection with error: %+v", err)
			continue
		}
		glog.V(5).Infof("client %+v accepted, calling the interceptor.", client.RemoteAddr())
		go interceptor(client, dstPort)
	}
}

func interceptor(client net.Conn, dstPort int) {
	var err error
	defer client.Close()
	server, err := net.Dial("tcp", ":"+fmt.Sprintf("%d", dstPort))
	if err != nil {
		glog.Errorf("fail to connect to destination with error: %+v", err)
		return
	}
	defer server.Close()
	glog.V(5).Infof("connection to destination server %v established, start intercepting", server.RemoteAddr())
	queue := make(chan []byte)
	pstop := make(chan struct{})
	// Starting parser per client with dedicated work queue
	go parser(queue, pstop)
	defer func() {
		glog.V(5).Infof("all done with client %+v and server %+v", client.RemoteAddr(), server.RemoteAddr())
		close(pstop)
	}()
	for {
		headerMsg := make([]byte, 6)
		if _, err := io.ReadAtLeast(client, headerMsg, 6); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}
		// Recovering common header first
		header, err := bmp.UnmarshalCommonHeader(headerMsg[:6])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			continue
		}
		// Allocating space for the message body
		msg := make([]byte, int(header.MessageLength)-6)
		// glog.V(5).Infof("Expected message lngth from client %+v is %d bytes", client.RemoteAddr(), int(header.MessageLength)-6)
		if _, err := io.ReadFull(client, msg); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}

		fullMsg := make([]byte, int(header.MessageLength))
		copy(fullMsg, headerMsg)
		copy(fullMsg[6:], msg)
		if _, err := server.Write(fullMsg); err != nil {
			glog.Errorf("fail to write to server %+v with error: %+v", server.RemoteAddr(), err)
			return
		}
		queue <- fullMsg
	}
}

func parser(queue chan []byte, stop chan struct{}) {
	for {
		select {
		case msg := <-queue:
			go parsingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
		default:
		}
	}
}

func parsingWorker(b []byte) {
	perPerHeaderLen := 0
	// Loop through all found Common Headers in the slice and process them
	for p := 0; p < len(b); {
		// Recovering common header first
		ch, err := bmp.UnmarshalCommonHeader(b[p : p+6])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		p += 6
		// glog.V(5).Infof("recovered common header, version: %d message length: %d message type: %d", ch.Version, ch.MessageLength, ch.MessageType)
		switch ch.MessageType {
		case 0:
			// *  Type = 0: Route Monitoring
			lb := p + int(ch.MessageLength-6)
			if lb > len(b) {
				lb = len(b)
			}
			// glog.V(6).Infof("found Route Monitoring message: %s, length: %d", messageHex(b), len(b))
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[p:lb])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				return
			}
			if rm.CheckSAFI(71) {
				// glog.V(5).Infof("route monitor message carries BGP-LS SAFI")
				// glog.V(6).Infof("raw route monitor of length: %d raw data: %s", len(b), messageHex(b))
				glog.V(6).Infof("parsed route monitor: \n%s", rm.String())
			} else {
				glog.V(5).Infof("route monitor message does not carry BGP-LS SAFI")
			}
			// glog.V(6).Infof("parsed route monitor: \n%s", rm.String())
		case 1:
			// *  Type = 1: Statistics Report
			//glog.V(5).Infof("found Stats Report")

			/*pph*/
			_, err := bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			//glog.V(5).Infof("recovered per peer header %+v", *pph)
			// Move buffer pointer for the length of Per-Peer header
			perPerHeaderLen = 42

			/*sr*/
			_, err = bmp.UnmarshalBMPStatsReportMessage(b[p+perPerHeaderLen : len(b)])
			if err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
			// glog.V(6).Infof("recovered per stats reports message %+v", *sr)
		case 2:
			// *  Type = 2: Peer Down Notification
			glog.V(5).Infof("Peer Down message")
			// glog.V(6).Infof("Message: %+v", b[p:len(b)])
		case 3:
			// *  Type = 3: Peer Up Notification
			glog.V(5).Infof("Peer Up message")
			/*pph*/ _, err := bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			// glog.V(5).Infof("recovered per peer header %+v", *pph)
			// Move buffer pointer for the length of Per-Peer header
			perPerHeaderLen = 42
			/*pu*/ _, err = bmp.UnmarshalPeerUpMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-6])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
			// glog.V(5).Infof("recovered per peer up message %+v", *pu)
			// glog.V(6).Infof("Sent Open %+v", *pu.SentOpen)
			// glog.V(6).Infof("Received Open %+v", *pu.ReceivedOpen)
		case 4:
			// *  Type = 4: Initiation Message
			glog.V(5).Infof("Initiation message")
			_, err := bmp.UnmarshalInitiationMessage(b[p : p+(int(ch.MessageLength)-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case 5:
			// *  Type = 5: Termination Message
			glog.V(5).Infof("Termination message")
		case 6:
			// *  Type = 6: Route Mirroring Message
			glog.V(5).Infof("Route Mirroring message")
		}
		perPerHeaderLen = 0
		p += (int(ch.MessageLength) - 6)
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

	// Starting Interceptor server
	go server(incoming, dstPort)

	stop := make(chan bool)
	<-stop
	os.Exit(0)
}
