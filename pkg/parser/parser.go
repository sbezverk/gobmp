package parser

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/tools"
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
	var bmpMsg bmp.Message
	// Loop through all found Common Headers in the slice and process them
	for m := 0; m < len(b); {
		bmpMsg.PeerHeader = nil
		bmpMsg.Payload = nil
		// Recovering common header first
		ch, err := bmp.UnmarshalCommonHeader(b[m:])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		p := m + bmp.CommonHeaderLength
		ph := p
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			fallthrough
		case bmp.StatsReportMsg:
			fallthrough
		case bmp.PeerDownMsg:
			fallthrough
		case bmp.PeerUpMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p:]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			p += bmp.PerPeerHeaderLength
		}
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[p:])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				if glog.V(5) {
					glog.Infof("common header content: %+v", ch)
					glog.Infof("per peer header content: %s", tools.MessageHex(b[ph:p]))
					glog.Infof("message content: %s", tools.MessageHex(b[p:m+int(ch.MessageLength)]))
				}
				return
			}
			bmpMsg.Payload = rm
		case bmp.StatsReportMsg:
			if bmpMsg.Payload, err = bmp.UnmarshalBMPStatsReportMessage(b[p:]); err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
		case bmp.PeerDownMsg:
			if bmpMsg.Payload, err = bmp.UnmarshalPeerDownMessage(b[p:]); err != nil {
				glog.Errorf("fail to recover BMP Peer Down message with error: %+v", err)
				return
			}
		case bmp.PeerUpMsg:
			if bmpMsg.Payload, err = bmp.UnmarshalPeerUpMessage(b[p:], bmpMsg.PeerHeader.IsRemotePeerIPv6()); err != nil {
				glog.Errorf("fail to recover BMP Peer Up message with error: %+v", err)
				return
			}
		case bmp.InitiationMsg:
			if _, err := bmp.UnmarshalInitiationMessage(b[p:]); err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case bmp.TerminationMsg:
			glog.V(5).Infof("Termination message")
			if glog.V(6) {
				glog.Infof("Content: %s", tools.MessageHex(b))
			}
		case bmp.RouteMirrorMsg:
			glog.V(5).Infof("Route Mirroring message")
			if glog.V(6) {
				glog.Infof("Content:%s", tools.MessageHex(b))
			}
		}
		m += int(ch.MessageLength)
		if producerQueue != nil && bmpMsg.Payload != nil {
			producerQueue <- bmpMsg
		}
	}
}
