package nats

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// Define constants for each topic name
const (
	peerTopic              = "gobmp.parsed.peer"
	unicastMessageTopic    = "gobmp.parsed.unicast_prefix"
	unicastMessageV4Topic  = "gobmp.parsed.unicast_prefix_v4"
	unicastMessageV6Topic  = "gobmp.parsed.unicast_prefix_v6"
	lsNodeMessageTopic     = "gobmp.parsed.ls_node"
	lsLinkMessageTopic     = "gobmp.parsed.ls_link"
	l3vpnMessageTopic      = "gobmp.parsed.l3vpn"
	l3vpnMessageV4Topic    = "gobmp.parsed.l3vpn_v4"
	l3vpnMessageV6Topic    = "gobmp.parsed.l3vpn_v6"
	lsPrefixMessageTopic   = "gobmp.parsed.ls_prefix"
	lsSRv6SIDMessageTopic  = "gobmp.parsed.ls_srv6_sid"
	evpnMessageTopic       = "gobmp.parsed.evpn"
	srPolicyMessageTopic   = "gobmp.parsed.sr_policy"
	srPolicyMessageV4Topic = "gobmp.parsed.sr_policy_v4"
	srPolicyMessageV6Topic = "gobmp.parsed.sr_policy_v6"
	flowspecMessageTopic   = "gobmp.parsed.flowspec"
	flowspecMessageV4Topic = "gobmp.parsed.flowspec_v4"
	flowspecMessageV6Topic = "gobmp.parsed.flowspec_v6"
	vplsMessageTopic       = "gobmp.parsed.vpls"
	statsMessageTopic      = "gobmp.parsed.statistics"
	rawMessageTopic        = "gobmp.raw"
)

var (
	maxReconnects = 10
	natsTimeout   = time.Second
	waitReconnect = time.Second
)

type publisher struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// topicForMessage maps a BMP message type to its NATS subject.
// Returns ("", false) for unknown types.
func topicForMessage(t int) (string, bool) {
	switch t {
	case bmp.PeerStateChangeMsg:
		return peerTopic, true
	case bmp.UnicastPrefixMsg:
		return unicastMessageTopic, true
	case bmp.UnicastPrefixV4Msg:
		return unicastMessageV4Topic, true
	case bmp.UnicastPrefixV6Msg:
		return unicastMessageV6Topic, true
	case bmp.LSNodeMsg:
		return lsNodeMessageTopic, true
	case bmp.LSLinkMsg:
		return lsLinkMessageTopic, true
	case bmp.L3VPNMsg:
		return l3vpnMessageTopic, true
	case bmp.L3VPNV4Msg:
		return l3vpnMessageV4Topic, true
	case bmp.L3VPNV6Msg:
		return l3vpnMessageV6Topic, true
	case bmp.LSPrefixMsg:
		return lsPrefixMessageTopic, true
	case bmp.LSSRv6SIDMsg:
		return lsSRv6SIDMessageTopic, true
	case bmp.EVPNMsg:
		return evpnMessageTopic, true
	case bmp.SRPolicyMsg:
		return srPolicyMessageTopic, true
	case bmp.SRPolicyV4Msg:
		return srPolicyMessageV4Topic, true
	case bmp.SRPolicyV6Msg:
		return srPolicyMessageV6Topic, true
	case bmp.FlowspecMsg:
		return flowspecMessageTopic, true
	case bmp.FlowspecV4Msg:
		return flowspecMessageV4Topic, true
	case bmp.FlowspecV6Msg:
		return flowspecMessageV6Topic, true
	case bmp.VPLSMsg:
		return vplsMessageTopic, true
	case bmp.StatsReportMsg:
		return statsMessageTopic, true
	case bmp.BMPRawMsg:
		return rawMessageTopic, true
	}
	return "", false
}

func (p *publisher) PublishMessage(t int, key []byte, msg []byte) error {
	topic, ok := topicForMessage(t)
	if !ok {
		return fmt.Errorf("nats publisher: unsupported BMP message type %d", t)
	}
	return p.produceMessage(topic, key, msg)
}

func (p *publisher) produceMessage(subject string, key []byte, data []byte) error {
	// use the header to pass the hash key
	header := nats.Header{}
	header.Set("Hash", string(key))

	msg := &nats.Msg{
		Subject: subject,
		Header:  header,
		Data:    data,
	}

	_, err := p.js.PublishMsg(msg)
	if err != nil {
		return err
	}

	return nil
}

func (p *publisher) Stop() {
	p.nc.Close()
}

func (p *publisher) createStreams() error {
	// Define the stream configuration
	streamConfig := &nats.StreamConfig{
		Name:      "goBMP",
		Subjects:  []string{"gobmp.parsed.*", "gobmp.raw"},
		Storage:   nats.FileStorage,
		Retention: nats.InterestPolicy,
		MaxMsgs:   -1, // No limit
		MaxBytes:  -1, // No limit
		MaxAge:    15 * time.Minute,
		Replicas:  1,
	}

	_, err := p.js.AddStream(streamConfig)
	if errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		if _, err = p.js.UpdateStream(streamConfig); err != nil {
			return fmt.Errorf("failed to update stream: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	return nil
}

// NewPublisher instantiates a new instance of a NATS publisher
func NewPublisher(natsSrv string) (pub.Publisher, error) {
	glog.Infof("Initializing NATS producer client")

	opts := []nats.Option{
		nats.Name("gobmp-producer"),
		nats.MaxReconnects(maxReconnects),
		nats.ReconnectWait(waitReconnect),
		nats.Timeout(natsTimeout),
	}

	nc, err := nats.Connect(natsSrv, opts...)
	if err != nil {
		return nil, err
	}

	// Create a JetStream context
	js, err := nc.JetStream()
	if err != nil {
		return nil, err
	}

	p := &publisher{
		nc: nc,
		js: js,
	}

	// Create the streams
	if err := p.createStreams(); err != nil {
		return nil, err
	}

	return p, nil
}
