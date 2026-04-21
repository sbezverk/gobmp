package parser

import (
	"errors"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/tools"
)

// Config holds parser configuration options.
type Config struct {
	// EnableRawMode when true produces RAW BMP messages without parsing
	EnableRawMode bool
	// SpeakerIP is the BMP speaker's IP from the TCP connection.
	// Set on all bmp.Message values for consistent router identity across message types.
	SpeakerIP string
}

// parser holds parser state and configuration.
type parser struct {
	queue         chan []byte
	producerQueue chan bmp.Message
	stop          chan struct{}
	config        *Config
}

// NewParser creates a new parser instance with the given configuration.
// If config is nil, default configuration is used (raw mode disabled).
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
		if pos+bmp.CommonHeaderLength > len(b) {
			glog.Errorf("truncated BMP message: pos=%d, remaining=%d", pos, len(b)-pos)
			return
		}
		ch, err := bmp.UnmarshalCommonHeader(b[pos : pos+bmp.CommonHeaderLength])
		if err != nil {
			glog.Errorf("fail to recover BMP message Common Header with error: %+v", err)
			return
		}
		if ch.MessageLength < bmp.CommonHeaderLength {
			glog.Errorf("invalid BMP message length: %d, must be at least %d", ch.MessageLength, bmp.CommonHeaderLength)
			return
		}
		remaining := len(b) - pos
		if uint64(ch.MessageLength) > uint64(remaining) {
			glog.Errorf("truncated BMP message: pos=%d, message length=%d, remaining=%d", pos, ch.MessageLength, remaining)
			return
		}
		// Convert once with overflow checking. After the guard above,
		// ch.MessageLength ≤ remaining ≤ len(b) ≤ maxInt, so this never
		// errors in practice, but the check documents the safety invariant
		// and is correct on 32-bit platforms.
		msgLen, err := ch.IntMessageLength()
		if err != nil {
			glog.Errorf("BMP message length overflows int: %+v", err)
			return
		}
		// Common header's length is a part  of the total message length
		// to get to next header, the pointer needs to advance by CommonHeaderLength
		pos += bmp.CommonHeaderLength
		switch ch.MessageType {
		case bmp.RouteMonitorMsg:
			if ch.MessageLength < uint32(bmp.CommonHeaderLength+bmp.PerPeerHeaderLength) {
				glog.Errorf("BMP RouteMonitor message too short for Per-Peer Header: length=%d, need at least %d",
					ch.MessageLength, bmp.CommonHeaderLength+bmp.PerPeerHeaderLength)
				return
			}
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+bmp.PerPeerHeaderLength]); err != nil {
				if errors.Is(err, bmp.ErrUnknownPeerType) {
					break // skip message, continue processing stream
				}
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			// Pass the BMP A flag (RFC 7854 §4.2) so AS_PATH width is authoritative
			// rather than heuristic. Is4ByteASN returns an error for PeerType3 — fall
			// back to the heuristic in that case by passing no argument.
			var as4opt []bool
			if is4, e := bmpMsg.PeerHeader.Is4ByteASN(); e == nil {
				as4opt = []bool{is4}
			}
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(b[pos+perPerHeaderLen:pos+msgLen-bmp.CommonHeaderLength], as4opt...)
			if err != nil {
				if errors.Is(err, bmp.ErrNotAnUpdate) {
					glog.V(5).Infof("skipping non-Update BGP message in route monitor: %+v", err)
					break
				}
				glog.Errorf("fail to recover BMP Route Monitoring with error: %+v", err)
				if glog.V(5) {
					glog.Infof("common header content: %+v", ch)
					glog.Infof("per peer header content: %s", tools.MessageHex(b[pos:pos+bmp.PerPeerHeaderLength]))
					glog.Infof("message content: %s", tools.MessageHex(b[pos+perPerHeaderLen:pos+msgLen-bmp.CommonHeaderLength]))
				}
				return
			}
			bmpMsg.Payload = rm
		case bmp.StatsReportMsg:
			if ch.MessageLength < uint32(bmp.CommonHeaderLength+bmp.PerPeerHeaderLength) {
				glog.Errorf("BMP StatsReport message too short for Per-Peer Header: length=%d, need at least %d",
					ch.MessageLength, bmp.CommonHeaderLength+bmp.PerPeerHeaderLength)
				return
			}
			// StatsReport body must also contain the 4-byte StatsCount field.
			if ch.MessageLength < uint32(bmp.CommonHeaderLength+bmp.PerPeerHeaderLength+4) {
				glog.Errorf("BMP StatsReport message too short for StatsCount: length=%d, need at least %d",
					ch.MessageLength, bmp.CommonHeaderLength+bmp.PerPeerHeaderLength+4)
				return
			}
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+bmp.PerPeerHeaderLength]); err != nil {
				if errors.Is(err, bmp.ErrUnknownPeerType) {
					break // skip message, continue processing stream
				}
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalBMPStatsReportMessage(b[pos+perPerHeaderLen : pos+msgLen-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Stats Reports message with error: %+v", err)
				return
			}
		case bmp.PeerDownMsg:
			if ch.MessageLength < uint32(bmp.CommonHeaderLength+bmp.PerPeerHeaderLength) {
				glog.Errorf("BMP PeerDown message too short for Per-Peer Header: length=%d, need at least %d",
					ch.MessageLength, bmp.CommonHeaderLength+bmp.PerPeerHeaderLength)
				return
			}
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+bmp.PerPeerHeaderLength]); err != nil {
				if errors.Is(err, bmp.ErrUnknownPeerType) {
					break // skip message, continue processing stream
				}
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerDownMessage(b[pos+perPerHeaderLen : pos+msgLen-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Peer Down message with error: %+v", err)
				return
			}
		case bmp.PeerUpMsg:
			if ch.MessageLength < uint32(bmp.CommonHeaderLength+bmp.PerPeerHeaderLength) {
				glog.Errorf("BMP PeerUp message too short for Per-Peer Header: length=%d, need at least %d",
					ch.MessageLength, bmp.CommonHeaderLength+bmp.PerPeerHeaderLength)
				return
			}
			if bmpMsg.PeerHeader, err = bmp.UnmarshalPerPeerHeader(b[pos : pos+bmp.PerPeerHeaderLength]); err != nil {
				if errors.Is(err, bmp.ErrUnknownPeerType) {
					break // skip message, continue processing stream
				}
				glog.Errorf("fail to recover BMP Per Peer Header with error: %+v", err)
				return
			}
			perPerHeaderLen = bmp.PerPeerHeaderLength
			if bmpMsg.Payload, err = bmp.UnmarshalPeerUpMessage(b[pos+perPerHeaderLen:pos+msgLen-bmp.CommonHeaderLength], bmpMsg.PeerHeader.IsRemotePeerIPv6()); err != nil {
				glog.Errorf("fail to recover BMP Peer Up message with error: %+v", err)
				return
			}
		case bmp.InitiationMsg:
			if _, err := bmp.UnmarshalInitiationMessage(b[pos : pos+msgLen-bmp.CommonHeaderLength]); err != nil {
				glog.Errorf("fail to recover BMP Initiation message with error: %+v", err)
				return
			}
		case bmp.TerminationMsg:
			tm, err := bmp.UnmarshalTerminationMessage(b[pos : pos+msgLen-bmp.CommonHeaderLength])
			if err != nil {
				glog.Errorf("fail to recover BMP Termination message with error: %+v", err)
			} else {
				glog.V(5).Infof("BMP session terminated: %s", tm.ReasonString())
				for _, s := range tm.Strings {
					glog.V(6).Infof("BMP termination detail: %s", s)
				}
			}
		case bmp.RouteMirrorMsg:
			glog.V(5).Infof("Route Mirroring message")
			if glog.V(6) {
				glog.Infof("Content:%s", tools.MessageHex(b))
			}
		}
		pos += msgLen - bmp.CommonHeaderLength
		if p.producerQueue != nil && bmpMsg.Payload != nil {
			bmpMsg.SpeakerIP = p.config.SpeakerIP
			// Use a stop-aware send: if shutdown is signalled while we are
			// blocked waiting for the producer to drain, we exit immediately
			// rather than deadlocking.
			select {
			case p.producerQueue <- bmpMsg:
			case <-p.stop:
				return
			}
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
		select {
		case p.producerQueue <- bmp.Message{PeerHeader: peerHeader, Payload: rm, SpeakerIP: p.config.SpeakerIP}:
		case <-p.stop:
			return
		}
	}
}
