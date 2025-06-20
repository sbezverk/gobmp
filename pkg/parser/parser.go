package parser

import (
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/tools"
)

// Parser dispatches workers upon request received from the channel
func Parser(queue chan []byte, producerQueue chan bmp.Message, stop chan struct{}) {
	// This is used to ensure that the calls to parsingWorker() occur "in sequence",
	// meaning Nth call has to complete before the (N+1)th call starts
	var wg sync.WaitGroup
	for {
		select {
		case msg := <-queue:
			wg.Add(1)
			go parsingWorker(msg, producerQueue, &wg)
			// Wait until the call above is done
			wg.Wait()
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func parsingWorker(b []byte, producerQueue chan bmp.Message, wg *sync.WaitGroup) {
	// To indicate to the caller that it is done
	defer wg.Done()

	perPerHeaderLen := 0
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
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p : p+bmp.PerPeerHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[p+perPerHeaderLen : p+int(ch.MessageLength)-bmp.CommonHeaderLength])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				if glog.V(5) {
					glog.Infof("common header content: %+v", ch)
					glog.Infof("per peer header content: %s", tools.MessageHex(b[p:p+bmp.PerPeerHeaderLength]))
					glog.Infof("message content: %s", tools.MessageHex(b[p+perPerHeaderLen:p+int(ch.MessageLength)-bmp.CommonHeaderLength]))
				}
				return
			}
			bmpMsg.Payload = rm
			p += perPerHeaderLen
		case bmp.StatsReportMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[p : p+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalBMPStatsReportMessage(b[p+perPerHeaderLen:]); err != nil {
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
			if bmpMsg.Payload, err = bmp.UnmarshalPeerUpMessage(b[p+perPerHeaderLen:p+int(ch.MessageLength)-bmp.CommonHeaderLength], bmpMsg.PeerHeader.IsRemotePeerIPv6()); err != nil {
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
			if glog.V(6) {
				glog.Infof("Content: %s", tools.MessageHex(b))
			}
		case bmp.RouteMirrorMsg:
			glog.V(5).Infof("Route Mirroring message")
			if glog.V(6) {
				glog.Infof("Content:%s", tools.MessageHex(b))
			}
		default:
			glog.Warningf("Unsupported message %d", ch.MessageType)
		}
		p += (int(ch.MessageLength) - bmp.CommonHeaderLength)
		if producerQueue != nil && bmpMsg.Payload != nil {
			glog.V(10).Infof("Sending msg to producer, hdr:<%+v> payload:<%+v>", bmpMsg.PeerHeader, bmpMsg.Payload)
			producerQueue <- bmpMsg
		}
	}
}
