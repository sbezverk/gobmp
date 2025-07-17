package nats

import (
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
	statsMessageTopic      = "gobmp.parsed.statistics"
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

func (p *publisher) PublishMessage(t int, key []byte, msg []byte) error {
	switch t {
	case bmp.PeerStateChangeMsg:
		return p.produceMessage(peerTopic, key, msg)
	case bmp.UnicastPrefixMsg:
		return p.produceMessage(unicastMessageTopic, key, msg)
	case bmp.UnicastPrefixV4Msg:
		return p.produceMessage(unicastMessageV4Topic, key, msg)
	case bmp.UnicastPrefixV6Msg:
		return p.produceMessage(unicastMessageV6Topic, key, msg)
	case bmp.LSNodeMsg:
		return p.produceMessage(lsNodeMessageTopic, key, msg)
	case bmp.LSLinkMsg:
		return p.produceMessage(lsLinkMessageTopic, key, msg)
	case bmp.L3VPNMsg:
		return p.produceMessage(l3vpnMessageTopic, key, msg)
	case bmp.L3VPNV4Msg:
		return p.produceMessage(l3vpnMessageV4Topic, key, msg)
	case bmp.L3VPNV6Msg:
		return p.produceMessage(l3vpnMessageV6Topic, key, msg)
	case bmp.LSPrefixMsg:
		return p.produceMessage(lsPrefixMessageTopic, key, msg)
	case bmp.LSSRv6SIDMsg:
		return p.produceMessage(lsSRv6SIDMessageTopic, key, msg)
	case bmp.EVPNMsg:
		return p.produceMessage(evpnMessageTopic, key, msg)
	case bmp.SRPolicyMsg:
		return p.produceMessage(srPolicyMessageTopic, key, msg)
	case bmp.SRPolicyV4Msg:
		return p.produceMessage(srPolicyMessageV4Topic, key, msg)
	case bmp.SRPolicyV6Msg:
		return p.produceMessage(srPolicyMessageV6Topic, key, msg)
	case bmp.FlowspecMsg:
		return p.produceMessage(flowspecMessageTopic, key, msg)
	case bmp.FlowspecV4Msg:
		return p.produceMessage(flowspecMessageV4Topic, key, msg)
	case bmp.FlowspecV6Msg:
		return p.produceMessage(flowspecMessageV6Topic, key, msg)
	case bmp.StatsReportMsg:
		return p.produceMessage(statsMessageTopic, key, msg)
	}

	return fmt.Errorf("not implemented")
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
		Subjects:  []string{"gobmp.parsed.*"},
		Storage:   nats.FileStorage,
		Retention: nats.InterestPolicy,
		MaxMsgs:   -1, // No limit
		MaxBytes:  -1, // No limit
		MaxAge:    15 * time.Minute,
		Replicas:  1,
	}

	// Try to create the stream, ignore if it already exists
	_, err := p.js.AddStream(streamConfig)
	if err != nil && err != nats.ErrStreamNameAlreadyInUse {
		return fmt.Errorf("failed to create stream: %v", err)
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
