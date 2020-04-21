package parser

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// Parser dispatches workers upon request received from the channel
func Parser(queue chan []byte, producerQueue chan bmp.Message, stop chan struct{}) {
	for {
		select {
		case msg := <-queue:
			go parsingWorker(msg, producerQueue)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func parsingWorker(b []byte, producerQueue chan bmp.Message) {
	perPerHeaderLen := 0
	// var jsonMsg []byte
	var bmpMsg bmp.Message
	// Loop through all found Common Headers in the slice and process them
	for p := 0; p < len(b); {
		bmpMsg.PeerHeader = nil
		bmpMsg.Payload = nil
		// Recovering common header first
		ch, err := bmp.UnmarshalCommonHeader(b[p : p+bmp.CommonHeaderLength])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		p += bmp.CommonHeaderLength
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-bmp.CommonHeaderLength])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				return
			}
			bmpMsg.Payload = rm
			p += perPerHeaderLen
		case bmp.StatsReportMsg:
			_, err := bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)])
			if err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if _, err = bmp.UnmarshalBMPStatsReportMessage(b[p+perPerHeaderLen:]); err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
		case bmp.PeerDownMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerDownMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Peer Down message with error: %+v", err)
				return
			}
			p += perPerHeaderLen
		case bmp.PeerUpMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerUpMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Peer Up message with error: %+v", err)
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
		if producerQueue != nil && bmpMsg.Payload != nil {
			producerQueue <- bmpMsg
		}
	}
}
