package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	kafka "github.com/sbezverk/gobmp/pkg/kafkaproducer"
)

var (
	dstPort  int
	srcPort  int
	kafkaSrv string
)

func init() {
	flag.IntVar(&srcPort, "source-port", 5000, "port exposed to outside")
	flag.IntVar(&dstPort, "destination-port", 5050, "port openBMP is listening")
	flag.StringVar(&kafkaSrv, "kafka-server", "", "URL to access Kafka server")
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
		glog.Errorf("failed to connect to destination with error: %+v", err)
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
		headerMsg := make([]byte, bmp.CommonHeaderLength)
		if _, err := io.ReadAtLeast(client, headerMsg, bmp.CommonHeaderLength); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}
		// Recovering common header first
		header, err := bmp.UnmarshalCommonHeader(headerMsg[:bmp.CommonHeaderLength])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			continue
		}
		// Allocating space for the message body
		msg := make([]byte, int(header.MessageLength)-bmp.CommonHeaderLength)
		if _, err := io.ReadFull(client, msg); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			return
		}

		fullMsg := make([]byte, int(header.MessageLength))
		copy(fullMsg, headerMsg)
		copy(fullMsg[bmp.CommonHeaderLength:], msg)
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
			return
		default:
		}
	}
}

func parsingWorker(b []byte) {
	perPerHeaderLen := 0
	// Loop through all found Common Headers in the slice and process them
	for p := 0; p < len(b); {
		// Recovering common header first
		ch, err := bmp.UnmarshalCommonHeader(b[p : p+bmp.CommonHeaderLength])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		p += bmp.CommonHeaderLength
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			lb := p + int(ch.MessageLength-bmp.CommonHeaderLength)
			if lb > len(b) {
				lb = len(b)
			}
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[p:lb])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				return
			}
			if rm.CheckSAFI(71) {
				glog.V(5).Infof("parsed route monitor: \n%s", rm.String())
				//				j, err := json.Marshal(&rm)
				//				if err != nil {
				//					glog.Errorf("fail to Marshal into JSON BMP Route Monitoring with error: %+v", err)
				//				}
				//				glog.V(5).Infof("JSON parsed route monitor: \n%s", string(j))
			}
		case bmp.StatsReportMsg:
			_, err := bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if _, err = bmp.UnmarshalBMPStatsReportMessage(b[p+perPerHeaderLen : len(b)]); err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
		case bmp.PeerDownMsg:
			glog.V(5).Infof("Peer Down message")
			glog.V(6).Infof("Message: %+v", b)
		case bmp.PeerUpMsg:
			if _, err := bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if _, err = bmp.UnmarshalPeerUpMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
		case bmp.InitiationMsg:
			if _, err := bmp.UnmarshalInitiationMessage(b[p : p+(int(ch.MessageLength)-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case bmp.TerminationMsg:
			glog.V(5).Infof("Termination message")
			glog.V(6).Infof("Message: %+v", b)
		case bmp.RouteMirrorMsg:
			glog.V(5).Infof("Route Mirroring message")
			glog.V(6).Infof("Message: %+v", b)
		}
		perPerHeaderLen = 0
		p += (int(ch.MessageLength) - bmp.CommonHeaderLength)
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
	// Initializing Kafka producer
	kc, err := kafka.NewKafkaProducerClient(kafkaSrv)
	if err != nil {
		glog.Warningf("Kafka producer is disabled, no Kafka server URL is provided.")
	} else {
		glog.V(6).Infof("Kafka producer was initialized: %+v", kc)
	}

	// Starting Interceptor server
	go server(incoming, dstPort)

	stop := make(chan bool)
	<-stop
	os.Exit(0)
}
