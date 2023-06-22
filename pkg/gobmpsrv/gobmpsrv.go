package gobmpsrv

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/parser"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// BMPServer defines methods to manage BMP Server
type BMPServer interface {
	Start()
	Stop()
}

type bmpServer struct {
	splitAF         bool
	intercept       bool
	publisher       pub.Publisher
	sourcePort      int
	destinationPort int
	incoming        net.Listener
	stop            chan struct{}
	passiveRouter   string
}

func (srv *bmpServer) Start() {
	// Starting bmp server server
	glog.Infof("Starting gobmp server on %s, intercept mode: %t\n", srv.incoming.Addr().String(), srv.intercept)
	go srv.server()
}

func (srv *bmpServer) Stop() {
	glog.Infof("Stopping gobmp server\n")
	if srv.publisher != nil {
		srv.publisher.Stop()
	}
	close(srv.stop)
}

func (srv *bmpServer) server() {
	// Create a channel for signaling retries from failed passive connections
	retryChan := make(chan struct{})
	retryCount := 0

	// Establish connection to passive router if specified
	if srv.passiveRouter != "" {
		go srv.passiveConnect(retryChan, retryCount)
	}

	// separate goroutine for handling incoming client connections
	go func() {
		for {
			client, err := srv.incoming.Accept()
			if err != nil {
				glog.Errorf("fail to accept client connection with error: %+v", err)
				continue
			}
			glog.V(5).Infof("client %+v accepted, calling bmpWorker", client.RemoteAddr())
			go srv.bmpWorker(client, nil)
		}
	}()

	// main goroutine for handling retrying passive connections
	for {
		<-retryChan
		if srv.passiveRouter != "" {
			glog.Infof("retrying connection to passive router")
			retryCount++
			go srv.passiveConnect(retryChan, retryCount)
		}
	}
}

func (srv *bmpServer) bmpWorker(client net.Conn, retryChan chan struct{}) {
	defer client.Close()
	var server net.Conn
	var err error
	if srv.intercept {
		server, err = net.Dial("tcp", ":"+fmt.Sprintf("%d", srv.destinationPort))
		if err != nil {
			glog.Errorf("failed to connect to destination with error: %+v", err)
			return
		}
		defer server.Close()
		glog.V(5).Infof("connection to destination server %v established, start intercepting", server.RemoteAddr())
	}
	var producerQueue chan bmp.Message
	prod := message.NewProducer(srv.publisher, srv.splitAF)
	prodStop := make(chan struct{})
	producerQueue = make(chan bmp.Message)
	// Starting messages producer per client with dedicated work queue
	go prod.Producer(producerQueue, prodStop)

	parserQueue := make(chan []byte)
	parsStop := make(chan struct{})
	// Starting parser per client with dedicated work queue
	go parser.Parser(parserQueue, producerQueue, parsStop)
	defer func() {
		glog.V(5).Infof("all done with client %+v", client.RemoteAddr())
		close(parsStop)
		close(prodStop)
	}()
	for {
		headerMsg := make([]byte, bmp.CommonHeaderLength)
		if _, err := io.ReadAtLeast(client, headerMsg, bmp.CommonHeaderLength); err != nil {
			glog.Errorf("fail to read from client %+v with error: %+v", client.RemoteAddr(), err)
			// Send a retry signal if channel is provided
			if retryChan != nil {
				retryChan <- struct{}{}
			}
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
		// Sending information to the server only in intercept mode
		if srv.intercept {
			if _, err := server.Write(fullMsg); err != nil {
				glog.Errorf("fail to write to server %+v with error: %+v", server.RemoteAddr(), err)
				return
			}
		}
		parserQueue <- fullMsg
	}
}

func (srv *bmpServer) passiveConnect(retryChan chan struct{}, retryCount int) {
	// Stop retrying after 10 attempts
	if retryCount > 10 {
		glog.Errorf("failed to connect to passive router after 10 retries")
		return
	}

	conn, err := net.DialTimeout("tcp", srv.passiveRouter, 10*time.Second)
	if err != nil {
		glog.Errorf("failed to connect to passive router with error: %+v", err)

		// Use a backoff timer to retry (30s * retryCount)
		time.Sleep(time.Duration(retryCount*30) * time.Second)

		// Signal tat the connection should be retried
		retryChan <- struct{}{}
		return
	}

	glog.Infof("connected to passive router %+v, calling bmpWorker", conn.RemoteAddr())
	go srv.bmpWorker(conn, retryChan)
}

// NewBMPServer instantiates a new instance of BMP Server
func NewBMPServer(sPort, dPort int, intercept bool, p pub.Publisher, splitAF bool, passiveRouter string) (BMPServer, error) {
	incoming, err := net.Listen("tcp", fmt.Sprintf(":%d", sPort))
	if err != nil {
		glog.Errorf("fail to setup listener on port %d with error: %+v", sPort, err)
		return nil, err
	}
	bmp := bmpServer{
		stop:            make(chan struct{}),
		sourcePort:      sPort,
		destinationPort: dPort,
		intercept:       intercept,
		publisher:       p,
		incoming:        incoming,
		splitAF:         splitAF,
		passiveRouter:   passiveRouter,
	}

	return &bmp, nil
}
