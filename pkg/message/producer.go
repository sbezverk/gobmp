package message

import (
	"crypto/md5"
	"encoding/hex"
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown
)

// PerTableProperties holds per-VRF/per-table properties
// Each VRF (identified by BGP-ID + Peer Distinguisher) has its own:
// - AddPath capability map (per AFI/SAFI)
// - Table Informational TLVs (including Table Name per RFC 9069)
type PerTableProperties struct {
	addPathCapable map[int]bool
	tableInfoTLVs  []bmp.InformationalTLV
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
	// initial identity cache. RouteMonitor and StatsReport workers wait on it so
	// active-mode initial routes do not race ahead of their PeerUp identity.
	speakerReady     chan struct{}
	speakerReadyOnce sync.Once
	// stopCh is set to the stop channel passed to Producer() before the dispatch
	// loop starts.  producingWorker goroutines select on it alongside speakerReady
	// so they can exit cleanly if the producer is shut down before any PeerUp
	// arrives (e.g. the connection drops before BGP session establishment).
	stopCh chan struct{}
	// Per-VRF table properties tracking (replaces global addPathCapable)
	// Key format: BGP-ID + Peer Distinguisher (e.g., "10.0.0.10:0")
	// Per RFC 9069 Section 4: uniquely identifies each Loc-RIB instance
	tableLock       sync.RWMutex
	tableProperties map[string]PerTableProperties
	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// collectorAdminID is the collector identifier string for OpenBMP binary header
	collectorAdminID string
	// adminHash is the MD5 hash of the admin ID for RAW messages
	adminHash    string
	identityLock sync.RWMutex
	identities   map[string]bmp.PeerIdentity
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	// Store stop before spawning any goroutine.  The Go memory model guarantees
	// that all goroutines created inside the loop below observe this write.
	p.stopCh = stop
	for {
		select {
		case msg := <-queue:
			switch msg.Payload.(type) {
			case *bmp.PeerUpMessage, *bmp.PeerDownMessage:
				// State changes update identity cache and publish in input order.
				p.producingWorker(msg)
			default:
				// Other message types carry an identity snapshot and can fan out.
				p.attachIdentitySnapshot(&msg)
				go p.producingWorker(msg)
			}
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
		peer = bmp.IdentityFromPeerHeader(*msg)
	}
	ph := *msg.PeerHeader
	ph.Identity = peer
	msg.PeerHeader = &ph
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
				p.identityLock.Unlock()
			}
		}
		if m, err := p.producePeerMessage(peerUP, msg, peer); err != nil {
			glog.Errorf("failed to produce peer message: %+v", err)
		} else {
			if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
				glog.Errorf("failed to process peer message with error: %+v", err)
			}
		}
	case *bmp.PeerDownMessage:
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
			peer = bmp.IdentityFromPeerHeader(msg)
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
		// Wait for the first identity before processing initial route messages.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
			return
		}
		p.attachIdentitySnapshot(&msg)
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		// Same cancellable wait as RouteMonitor above.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
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

// GetAddPathCapability returns AddPath capability map for a specific table
// Returns nil if table doesn't exist (caller must handle gracefully)
// Accessing nil map in Go returns zero value (false) for all keys, which is safe
// Per RFC 7911 Section 3: AddPath capability is advertised per BGP session
func (p *producer) GetAddPathCapability(tableKey string) map[int]bool {
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()

	if props, ok := p.tableProperties[tableKey]; ok {
		return props.addPathCapable
	}

	// Return nil - parsers will treat nil map as "no AddPath capability"
	// This is safe: accessing nil map returns zero value (false)
	return nil
}

// GetTableName returns table name from Table Informational TLVs
// Used for populating TableName field in LocRIB routes
// Per RFC 9069 Section 5: TLV Type 3 contains the Table Name string
func (p *producer) GetTableName(bgpID, rd string) string {
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()

	tableKey := bgpID + rd
	tn := ""

	if properties, ok := p.tableProperties[tableKey]; ok {
		for _, tlv := range properties.tableInfoTLVs {
			if tlv.InformationType == 3 {
				// Information is []byte, convert to string
				tn += string(tlv.Information)
			}
		}
	}

	return tn
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher, splitAF bool) Producer {
	return &producer{
		publisher:       publisher,
		splitAF:         splitAF,
		tableProperties: make(map[string]PerTableProperties),
		speakerReady:    make(chan struct{}),
		identities:      make(map[string]bmp.PeerIdentity),
	}
}
