package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

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
		i += 6
		glog.V(5).Infof("recovered common header, version: %d message length: %d message type: %d", ch.Version, ch.MessageLength, ch.MessageType)
		// TODO Figure out reliable way to detect if Per-Peer Header exist
		if ch.MessageLength > 64 {
			pph, err := UnmarshalPerPeerHeader(b[i : i+int(ch.MessageLength-6)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			glog.V(5).Infof("recovered per peer heder %+v", *pph)
			// Move buffer pointer for the length of Per-Peer header
			i += 42
		}
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
			pu, err := UnmarshalPeerUpMessage(b[i : i+int(ch.MessageLength-6-42)])
			if err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
			glog.V(5).Infof("recovered per peer up message %+v", *pu)
			i += int(ch.MessageLength) - 6 - 42
		case 4:
			// *  Type = 4: Initiation Message
			glog.V(5).Infof("found Initiation message")
			_, err := UnmarshalInitiationMessage(b[i : i+int(ch.MessageLength-6)])
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
		i += int(ch.MessageLength - 6)
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

// UnmarshalCommonHeader processes Common Header and returns BMPCommonHeader object
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

// UnmarshalInitiationMessage processes Initiation Message and returns BMPInitiationMessage object
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

// UnmarshalTLV builds a slice of Informational TLVs
func UnmarshalTLV(b []byte) ([]BMPInformationalTLV, error) {
	tlvs := make([]BMPInformationalTLV, 0)
	for i := 0; i < len(b); {
		// Extracting TLV type 2 bytes
		t := int16(binary.BigEndian.Uint16(b[i : i+2]))
		// Extracting TLV length
		l := int16(binary.BigEndian.Uint16(b[i+2 : i+4]))
		if l > int16(len(b)-(i+4)) {
			return nil, fmt.Errorf("invalid tlv length %d", l)
		}
		v := b[i+4 : i+4+int(l)]
		tlvs = append(tlvs, BMPInformationalTLV{
			InformationType:   t,
			InformationLength: l,
			Information:       v,
		})
		i += 4 + int(l)
	}

	return tlvs, nil
}

// BMPPerPeerHeader defines BMP Per-Peer Header per rfc7854
type BMPPerPeerHeader struct {
	PeerType          byte
	FlagV             bool
	FlagL             bool
	FlagA             bool
	PeerDistinguisher []byte
	PeerAddress       []byte
	PeerAS            int32
	PeerBGPID         []byte
	PeerTimestamp     time.Duration
}

// UnmarshalPerPeerHeader processes Per-Peer header
func UnmarshalPerPeerHeader(b []byte) (*BMPPerPeerHeader, error) {
	pph := &BMPPerPeerHeader{
		PeerDistinguisher: make([]byte, 8),
		PeerAddress:       make([]byte, 14),
		PeerBGPID:         make([]byte, 4),
	}
	// Extracting Peer type
	// *  Peer Type = 0: Global Instance Peer
	// *  Peer Type = 1: RD Instance Peer
	// *  Peer Type = 2: Local Instance Peer
	switch b[0] {
	case 0:
	case 1:
	case 2:
	default:
		return nil, fmt.Errorf("invalid peer type, expected between 0 and 2 found %d", b[0])
	}
	pph.PeerType = b[0]
	pph.FlagV = b[1]&0x80 == 0x80
	pph.FlagL = b[1]&0x40 == 0x40
	pph.FlagA = b[1]&0x20 == 0x20
	// RD 8 bytes
	copy(pph.PeerDistinguisher, b[4:12])
	// Peer Address 16 bytes
	copy(pph.PeerAddress, b[12:26])
	pph.PeerAS = int32(binary.BigEndian.Uint32(b[26:30]))
	copy(pph.PeerBGPID, b[30:34])
	pph.PeerTimestamp = time.Duration(binary.BigEndian.Uint64(b[34:42]))

	return pph, nil
}

// BMPPeerUpMessage defines BMPPeerUpMessage per rfc7854
type BMPPeerUpMessage struct {
	LocalAddress []byte
	LocalPort    int16
	RemotePort   int16
	SentOpen     []byte
	ReceivedOpen []byte
	Information  []BMPInformationalTLV
}

// UnmarshalPeerUpMessage processes Peer Up message and returns BMPPeerUpMessage object
func UnmarshalPeerUpMessage(b []byte) (*BMPPeerUpMessage, error) {
	pu := &BMPPeerUpMessage{
		LocalAddress: make([]byte, 16),
		//		SentOpen:     make([]byte, 16),
		//		ReceivedOpen: make([]byte, 16),
		Information: make([]BMPInformationalTLV, 0),
	}
	p := 0
	copy(pu.LocalAddress, b[:16])
	p += 16
	pu.LocalPort = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	pu.RemotePort = int16(binary.BigEndian.Uint16(b[p : p+2]))
	p += 2
	l1 := int16(binary.BigEndian.Uint16(b[p+16 : p+16+2]))
	pu.SentOpen = make([]byte, l1)
	copy(pu.SentOpen, b[p:p+int(l1)])
	p += int(l1)
	l2 := int16(binary.BigEndian.Uint16(b[p+16 : p+16+2]))
	pu.ReceivedOpen = make([]byte, l2)
	copy(pu.ReceivedOpen, b[p:p+int(l2)])
	p += int(l2)
	if len(b) > int(p) {
		// Since pointer p does not point to the end of buffer,
		// then processing Informational TLVs
		tlvs, err := UnmarshalTLV(b[p : len(b)-int(p)])
		if err != nil {
			return nil, err
		}
		pu.Information = tlvs
	}
	return pu, nil
}
