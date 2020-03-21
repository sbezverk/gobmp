package parser

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// Parser dispatches workers upon request received from the channel
func Parser(queue chan []byte, stop chan struct{}) {
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
