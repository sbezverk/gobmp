package parser

import (
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/tools"
)

// Config holds parser configuration options
type Config struct {
	// EnableRawMode when true produces RAW BMP messages without parsing
	EnableRawMode bool
	// SpeakerIP is the BMP speaker's IP from the TCP connection.
	// Passed through to bmp.Message for message types without a per-peer header.
	SpeakerIP string
}

// parser holds parser state and configuration
type parser struct {
	queue         chan []byte
	producerQueue chan bmp.Message
	stop          chan struct{}
	config        *Config
}

// NewParser creates a new parser instance with the given configuration
// If config is nil, default configuration is used (raw mode disabled)
func NewParser(queue chan []byte, producerQueue chan bmp.Message, stop chan struct{}, config *Config) *parser {
	if config == nil {
		config = &Config{EnableRawMode: false}
	}
	return &parser{
		queue:         queue,
		producerQueue: producerQueue,
		stop:          stop,
		config:        config,
	}
}

// Start begins processing messages from the queue
func (p *parser) Start() {
	for {
		select {
		case msg := <-p.queue:
			go p.parsingWorker(msg)
		case <-p.stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

// Parser provides backward compatibility with the old function-based API
// Deprecated: Use NewParser and Start() method instead
func Parser(queue chan []byte, producerQueue chan bmp.Message, stop chan struct{}) {
	p := NewParser(queue, producerQueue, stop, nil)
	p.Start()
}

func (p *parser) parsingWorker(b []byte) {
	// If raw mode is enabled, send the entire message as-is
	if p.config.EnableRawMode {
		p.sendRawMessage(b)
		return
	}

	// Otherwise, parse the message normally
	perPerHeaderLen := 0
	var bmpMsg bmp.Message
	// Loop through all found Common Headers in the slice and process them
	for pos := 0; pos < len(b); {
		bmpMsg.PeerHeader = nil
		bmpMsg.Payload = nil
		// Recovering common header first
		ch, err := bmp.UnmarshalCommonHeader(b[pos : pos+bmp.CommonHeaderLength])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		pos += bmp.CommonHeaderLength
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+bmp.PerPeerHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[pos+perPerHeaderLen : pos+int(ch.MessageLength)-bmp.CommonHeaderLength])
			if err != nil {
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				if glog.V(5) {
					glog.Infof("common header content: %+v", ch)
					glog.Infof("per peer header content: %s", tools.MessageHex(b[pos:pos+bmp.PerPeerHeaderLength]))
					glog.Infof("message content: %s", tools.MessageHex(b[pos+perPerHeaderLen:pos+int(ch.MessageLength)-bmp.CommonHeaderLength]))
				}
				return
			}
			bmpMsg.Payload = rm
			pos += perPerHeaderLen
		case bmp.StatsReportMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalBMPStatsReportMessage(b[pos+perPerHeaderLen:]); err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
			pos += perPerHeaderLen
		case bmp.PeerDownMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerDownMessage(b[pos+perPerHeaderLen : pos+int(ch.MessageLength)-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Peer Down message with error: %+v", err)
				return
			}
			pos += perPerHeaderLen
		case bmp.PeerUpMsg:
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+int(ch.MessageLength-bmp.CommonHeaderLength)]); err != nil {
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerUpMessage(b[pos+perPerHeaderLen:pos+int(ch.MessageLength)-bmp.CommonHeaderLength], bmpMsg.PeerHeader.IsRemotePeerIPv6()); err != nil {
				glog.Errorf("fail to recover BMP Peer Up message with error: %+v", err)
				return
			}
			pos += perPerHeaderLen
		case bmp.InitiationMsg:
			if _, err := bmp.UnmarshalInitiationMessage(b[pos : pos+(int(ch.MessageLength)-bmp.CommonHeaderLength)]); err != nil {
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
		pos += (int(ch.MessageLength) - bmp.CommonHeaderLength)
		if p.producerQueue != nil && bmpMsg.Payload != nil {
			bmpMsg.SpeakerIP = p.config.SpeakerIP
			p.producerQueue <- bmpMsg
		}
	}
}

// sendRawMessage sends the entire BMP message as a RAW message without parsing
func (p *parser) sendRawMessage(b []byte) {
	// Unmarshal the raw message
	rm, err := bmp.UnmarshalBMPRawMessage(b)
	if err != nil {
		glog.Errorf("fail to create BMP RAW message with error: %+v", err)
		return
	}

	// Extract peer header if present (needed for OpenBMP format)
	var peerHeader *bmp.PerPeerHeader
	if len(b) >= bmp.CommonHeaderLength+bmp.PerPeerHeaderLength {
		ch, err := bmp.UnmarshalCommonHeader(b[:bmp.CommonHeaderLength])
		if err == nil {
			// Only extract peer header for message types that have it
			switch ch.MessageType {
			case bmp.RouteMonitorMsg, bmp.StatsReportMsg, bmp.PeerDownMsg, bmp.PeerUpMsg:
				peerHeader, _ = bmp.UnmarshalPerPeerHeader(b[bmp.CommonHeaderLength : bmp.CommonHeaderLength+bmp.PerPeerHeaderLength])
			}
		}
	}

	// Send the raw message
	if p.producerQueue != nil {
		p.producerQueue <- bmp.Message{
			PeerHeader: peerHeader,
			Payload:    rm,
			SpeakerIP:  p.config.SpeakerIP,
		}
	}
}
