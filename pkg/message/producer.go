package message

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown
)

// tableReadyEntry holds a readiness channel and a flag to prevent double-close
// if duplicate PeerUp messages arrive for the same table key.
type tableReadyEntry struct {
	ch     chan struct{}
	closed bool
}

// PerTableProperties holds per-VRF/per-table properties
// Each VRF (identified by BGP-ID + Peer Distinguisher) has its own:
// - AddPath capability map (per AFI/SAFI)
// - Table Informational TLVs (including Table Name per RFC 9069)
type PerTableProperties struct {
	addPathCapable map[int]bool
	tableInfoTLVs  []bmp.InformationalTLV
	localIP        string
	localHash      string
}

// Config holds producer configuration options
type Config struct {
	// AdminID is the collector identifier for RAW messages
	// Used to generate collector hash for OpenBMP compatibility
	AdminID string
	// TransportIP is the TCP source IP of the BMP speaker. It is known at
	// connection time and immutable for the lifetime of this producer.
	TransportIP string
}

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
	SetConfig(config *Config) error
}

type producer struct {
	publisher     pub.Publisher
	transportIP   string
	transportHash string
	// stopCh is set to the stop channel passed to Producer() before the dispatch
	// loop starts. producingWorker goroutines select on it alongside per-table
	// ready channels so they can exit cleanly if the producer is shut down before
	// the relevant PeerUp arrives.
	stopCh chan struct{}
	// tableReady maps table keys to per-table readiness entries.
	// Each entry holds an open channel that is closed exactly once when the
	// table's PeerUp goroutine has fully populated tableProperties. The closed
	// flag prevents a double-close panic if duplicate PeerUp messages arrive.
	// RouteMonitor and StatsReport goroutines block on the per-table channel
	// rather than a single global channel, so a route burst for one VRF cannot
	// be unblocked by a PeerUp for a different VRF.
	tableReady     map[string]*tableReadyEntry
	tableReadyLock sync.Mutex
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
	adminHash string
}

// tableReadyCh returns the ready channel for the given table key, creating it
// if it does not yet exist. The returned channel is closed by markTableReady
// once PeerUp for that table has fully populated tableProperties.
func (p *producer) tableReadyCh(tableKey string) chan struct{} {
	p.tableReadyLock.Lock()
	defer p.tableReadyLock.Unlock()
	if e, ok := p.tableReady[tableKey]; ok {
		return e.ch
	}
	e := &tableReadyEntry{ch: make(chan struct{})}
	p.tableReady[tableKey] = e
	return e.ch
}

// markTableReady closes the per-table ready channel for tableKey, unblocking
// any RouteMonitor/StatsReport goroutines waiting for that table's PeerUp.
// Must be called after tableProperties[tableKey] has been written.
// Safe to call multiple times for the same generation: duplicate PeerUp
// messages are silently ignored after the first close.
func (p *producer) markTableReady(tableKey string) {
	p.tableReadyLock.Lock()
	e, ok := p.tableReady[tableKey]
	if !ok {
		e = &tableReadyEntry{ch: make(chan struct{})}
		p.tableReady[tableKey] = e
	}
	if !e.closed {
		e.closed = true
		p.tableReadyLock.Unlock()
		close(e.ch)
		return
	}
	p.tableReadyLock.Unlock()
}

// resetTableReady closes the current per-table channel (if not already closed)
// to unblock any goroutines that are still waiting on it, then installs a new
// open channel for the next PeerUp session. Called from PeerDown before
// tableProperties is deleted.
func (p *producer) resetTableReady(tableKey string) {
	p.tableReadyLock.Lock()
	defer p.tableReadyLock.Unlock()
	if e, ok := p.tableReady[tableKey]; ok && !e.closed {
		// Close the channel so goroutines blocked on this generation wake up.
		// They will subsequently detect that tableProperties is gone and drop
		// their message rather than emitting it with empty router identity.
		e.closed = true
		close(e.ch)
	}
	p.tableReady[tableKey] = &tableReadyEntry{ch: make(chan struct{})}
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	// Store stop before spawning any goroutine. The Go memory model guarantees
	// that all goroutines created inside the loop below observe this write.
	p.stopCh = stop
	for {
		select {
		case msg := <-queue:
			// Snapshot the per-table ready channel at dequeue time for
			// RouteMonitor/StatsReport messages. This ensures the goroutine
			// waits on the channel generation that was current when the message
			// was received, not a newer one installed by a later PeerDown+PeerUp.
			var readyCh chan struct{}
			switch msg.Payload.(type) {
			case *bmp.RouteMonitor, *bmp.StatsReport:
				if msg.PeerHeader != nil {
					readyCh = p.tableReadyCh(msg.PeerHeader.GetTableKey())
				}
			}
			go p.producingWorker(msg, readyCh)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func (p *producer) producingWorker(msg bmp.Message, readyCh chan struct{}) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		p.producePeerMessage(peerUP, msg)
	case *bmp.PeerDownMessage:
		p.producePeerMessage(peerDown, msg)
	case *bmp.RouteMonitor:
		// Wait until PeerUp for this specific table has populated tableProperties.
		// readyCh was snapshotted at dequeue time in Producer(), so we wait on
		// the channel generation that was current when this message was received.
		if readyCh != nil {
			select {
			case <-readyCh:
			case <-p.stopCh:
				return
			}
			// PeerDown may have woken us by closing the old channel before a new
			// PeerUp arrived. If tableProperties is gone, drop the message rather
			// than producing it with empty router identity.
			if localIP, _ := p.peerLocal(msg.PeerHeader.GetTableKey()); localIP == "" {
				return
			}
		}
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		// Same per-table wait and stale-table check as RouteMonitor above.
		if readyCh != nil {
			select {
			case <-readyCh:
			case <-p.stopCh:
				return
			}
			if localIP, _ := p.peerLocal(msg.PeerHeader.GetTableKey()); localIP == "" {
				return
			}
		}
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

	if config.TransportIP != "" {
		if p.transportIP != "" && p.transportIP != config.TransportIP {
			return fmt.Errorf("TransportIP is immutable: already set to %q, cannot change to %q", p.transportIP, config.TransportIP)
		}
		if p.transportIP == "" {
			p.transportIP = config.TransportIP
			hash := md5.Sum([]byte(config.TransportIP))
			p.transportHash = hex.EncodeToString(hash[:])
		}
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

// peerLocal returns the BGP local peering address and its hash for the given
// table key. Returns empty strings if the peer is not yet known.
func (p *producer) peerLocal(tableKey string) (localIP, localHash string) {
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()
	if props, ok := p.tableProperties[tableKey]; ok {
		localIP = props.localIP
		localHash = props.localHash
	}
	return
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher, splitAF bool) Producer {
	return &producer{
		publisher:       publisher,
		splitAF:         splitAF,
		tableProperties: make(map[string]PerTableProperties),
		tableReady:      make(map[string]*tableReadyEntry),
	}
}
