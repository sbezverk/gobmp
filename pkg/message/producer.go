package message

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown

	// Pre-PeerUp traffic is unusual but can be observed during a router/BMP
	// reconnect. Keep the compatibility buffer bounded so a peer that never
	// reaches Peer Up cannot retain an unbounded amount of parsed data.
	maxPrePeerUpMessages = 256
	maxPrePeerUpBytes    = 8 << 20
)

// PerTableProperties holds Loc-RIB table informational TLVs per RFC 9069.
type PerTableProperties struct {
	tableInfoTLVs []bmp.InformationalTLV
}

// Config holds producer configuration options
type Config struct {
	// AdminID is the collector identifier for RAW messages
	// Used to generate collector hash for OpenBMP compatibility
	AdminID string
}

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
	SetConfig(config *Config) error
}

type producer struct {
	publisher pub.Publisher

	// speakerReady is closed once the first valid PeerUp has established the
	// initial identity and negotiated properties. Earlier RouteMonitor and
	// StatsReport messages are buffered; replay requires their own installed
	// peer state and, for Loc-RIB routes, explicitly described families.
	speakerReady     chan struct{}
	speakerReadyOnce sync.Once
	prePeerUp        []bmp.Message
	prePeerUpBytes   int
	// tableLock protects Loc-RIB table TLVs and per-peer ADD-PATH properties.
	// Table names use BGP-ID + raw distinguisher; ADD-PATH uses PeerIdentity
	// so distinct BGP sessions do not overwrite their negotiated wire format.
	tableLock       sync.RWMutex
	tableProperties map[string]PerTableProperties
	peerAddPath     map[string]peerAddPathProperties
	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// collectorAdminID is the collector identifier string for OpenBMP binary header
	collectorAdminID string
	// adminHash is the MD5 hash of the admin ID for RAW messages
	adminHash    string
	identityLock sync.RWMutex
	identities   map[string]bmp.PeerIdentity
	speakerID    bmp.PeerIdentity
}

// Producer publishes one BMP connection's messages in input order.
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	for {
		select {
		case msg, ok := <-queue:
			if !ok {
				return
			}
			p.producingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func (p *producer) attachIdentitySnapshot(msg *bmp.Message) {
	if msg == nil || msg.PeerHeader == nil {
		return
	}

	var peer bmp.PeerIdentity
	var peerExists bool
	peerKey := msg.PeerHeader.PeerIdentity()
	if peerKey != "" {
		p.identityLock.RLock()
		peer, peerExists = p.identities[peerKey]
		p.identityLock.RUnlock()
	}
	if !peerExists {
		peer = p.identityFromHeaderFallback(*msg)
	}
	ph := *msg.PeerHeader
	ph.Identity = peer
	msg.PeerHeader = &ph
}

func (p *producer) identityFromHeaderFallback(msg bmp.Message) bmp.PeerIdentity {
	peer := bmp.IdentityFromPeerHeader(msg)

	p.identityLock.RLock()
	speakerID := p.speakerID
	p.identityLock.RUnlock()

	if speakerID.RouterIP == "" && speakerID.RouterHash == "" {
		return peer
	}

	peer.SpeakerIP = speakerID.SpeakerIP
	peer.SpeakerHash = speakerID.SpeakerHash
	peer.RouterIP = speakerID.RouterIP
	peer.RouterHash = speakerID.RouterHash
	return peer
}

func prePeerUpMessageBytes(msg bmp.Message) int {
	size := 0
	switch payload := msg.Payload.(type) {
	case *bmp.RouteMonitor:
		if payload != nil && payload.Update != nil {
			size += len(payload.Update.WithdrawnRoutes) + len(payload.Update.NLRI)
			for _, attr := range payload.Update.PathAttributes {
				size += len(attr.Attribute)
			}
		}
	case *bmp.StatsReport:
		if payload != nil {
			for _, tlv := range payload.StatsTLV {
				size += len(tlv.Information)
			}
		}
	}
	// Include a small fixed allowance for the parsed structure itself. The
	// limit is intentionally approximate; its purpose is to bound retained
	// payload data, not to report an exact heap size.
	return size + 256
}

func (p *producer) bufferPrePeerUp(msg bmp.Message) {
	messageBytes := prePeerUpMessageBytes(msg)
	if len(p.prePeerUp) >= maxPrePeerUpMessages || p.prePeerUpBytes+messageBytes > maxPrePeerUpBytes {
		glog.Warningf("pre-Peer Up buffer full, dropping %T", msg.Payload)
		return
	}
	p.prePeerUp = append(p.prePeerUp, msg)
	p.prePeerUpBytes += messageBytes
}

func (p *producer) discardPrePeerUp() {
	p.prePeerUp = nil
	p.prePeerUpBytes = 0
}

func (p *producer) prePeerUpReady(msg bmp.Message) bool {
	if msg.PeerHeader == nil || msg.PeerHeader.PeerIdentity() == "" {
		return false
	}
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()
	properties, known := p.peerAddPath[msg.PeerHeader.PeerIdentity()]
	if !known {
		return false
	}
	route, isRoute := msg.Payload.(*bmp.RouteMonitor)
	if msg.PeerHeader.PeerType != bmp.PeerType3 || !isRoute {
		return true
	}
	if route == nil || route.Update == nil {
		return false
	}
	update := route.Update
	// RFC 9069 Sections 5.2 and 6.1.1 allow separate family Peer Ups for
	// one Loc-RIB identity. Membership, including false, describes a family;
	// an absent family does not establish its NLRI wire format.
	if afi, safi, eor := endOfRIBFamily(update); eor {
		_, known := properties.in[bgp.AFISAFI{AFI: afi, SAFI: safi}]
		return known
	}
	if len(update.NLRI) != 0 || len(update.WithdrawnRoutes) != 0 || update.WithdrawnRoutesLength != 0 {
		if _, known := properties.in[bgp.AFISAFI{AFI: 1, SAFI: 1}]; !known {
			return false
		}
	}
	for _, attr := range update.PathAttributes {
		if attr.AttributeType != bgp.MP_REACH_NLRI && attr.AttributeType != bgp.MP_UNREACH_NLRI {
			continue
		}
		if len(attr.Attribute) < 3 {
			return false
		}
		family := bgp.AFISAFI{AFI: binary.BigEndian.Uint16(attr.Attribute[:2]), SAFI: attr.Attribute[2]}
		if _, known := properties.in[family]; !known {
			return false
		}
	}
	return true
}

func (p *producer) replayPrePeerUp() {
	buffered := p.prePeerUp
	p.discardPrePeerUp()
	for _, msg := range buffered {
		if !p.prePeerUpReady(msg) {
			glog.Warningf("pre-Peer Up replay dropping %T: peer/family state is missing or indeterminate", msg.Payload)
			continue
		}
		p.producingWorker(msg)
	}
}

func (p *producer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		var peer bmp.PeerIdentity
		var peerExists bool
		if msg.PeerHeader != nil {
			peerID := msg.PeerHeader.PeerIdentity()
			peer = bmp.IdentityFromPeerUp(msg)
			if peerID != "" {
				p.identityLock.Lock()
				if p.identities == nil {
					p.identities = make(map[string]bmp.PeerIdentity)
				}
				cachedPeer, ok := p.identities[peerID]
				peerExists = ok
				if !peerExists {
					p.identities[peerID] = peer
					glog.V(5).Infof("New peer identity stored for peer %s: %s", peerID, peer)
				} else if !cachedPeer.IsEqual(peer) {
					glog.Warningf("Peer identity changed for peer %s: old=%s, new=%s", peerID, cachedPeer, peer)
					p.identities[peerID] = peer
				} else {
					glog.V(5).Infof("Duplicate PeerUP message for peer %s: %s", peerID, peer)
				}
				if p.speakerID.RouterIP == "" || !isSpecificAddress(p.speakerID.RouterIP) {
					p.speakerID = peer
				}
				p.identityLock.Unlock()
			}
		}
		if m, err := p.producePeerMessage(peerUP, msg, peer); err != nil {
			glog.Errorf("failed to produce peer message: %+v", err)
		} else {
			if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
				glog.Errorf("failed to process peer message with error: %+v", err)
			}
			p.replayPrePeerUp()
		}
	case *bmp.PeerDownMessage:
		select {
		case <-p.speakerReady:
		default:
			p.discardPrePeerUp()
		}
		var m *PeerStateChange
		var err error
		if msg.PeerHeader == nil {
			glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
			return
		}
		var peer bmp.PeerIdentity
		var peerExists bool
		peerID := msg.PeerHeader.PeerIdentity()
		if peerID != "" {
			p.identityLock.RLock()
			peer, peerExists = p.identities[peerID]
			p.identityLock.RUnlock()
		}

		if !peerExists {
			peer = p.identityFromHeaderFallback(msg)
		}
		if m, err = p.producePeerMessage(peerDown, msg, peer); err != nil {
			glog.Errorf("failed to produce peer message: %+v", err)
			return
		}
		// Remove the peer identity from the cache if it exists, since the peer is now down
		if peerExists {
			p.identityLock.Lock()
			delete(p.identities, peerID)
			p.identityLock.Unlock()
		}
		// Publish using the identity snapshot captured before cache removal.
		if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
			glog.Errorf("failed to process peer message with error: %+v", err)
		}
	case *bmp.RouteMonitor:
		select {
		case <-p.speakerReady:
		default:
			p.bufferPrePeerUp(msg)
			return
		}
		p.attachIdentitySnapshot(&msg)
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		select {
		case <-p.speakerReady:
		default:
			p.bufferPrePeerUp(msg)
			return
		}
		p.attachIdentitySnapshot(&msg)
		p.produceStatsMessage(msg)
	case *bmp.RawMessage:
		p.produceRawMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to the producer, ignoring it...", obj)
	}
}

// SetConfig configures the producer with the given configuration
// Must be called before starting the producer if RAW message support is needed
func (p *producer) SetConfig(config *Config) error {
	if config == nil {
		return nil
	}

	if config.AdminID != "" {
		// Store collector admin ID for OpenBMP binary header
		p.collectorAdminID = config.AdminID
		// Generate MD5 hash of admin ID for OpenBMP collector hash
		hash := md5.Sum([]byte(config.AdminID))
		p.adminHash = hex.EncodeToString(hash[:])
	}

	return nil
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher, splitAF bool) Producer {
	return &producer{
		publisher:       publisher,
		splitAF:         splitAF,
		tableProperties: make(map[string]PerTableProperties),
		peerAddPath:     make(map[string]peerAddPathProperties),
		speakerReady:    make(chan struct{}),
		identities:      make(map[string]bmp.PeerIdentity),
	}
}
