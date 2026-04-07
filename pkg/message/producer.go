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
	speakerIP   string
	speakerHash string
	// speakerReady is closed exactly once (by speakerReadyOnce) when the first
	// PeerUp message has been processed and speakerIP/speakerHash are populated.
	// RouteMonitor and StatsReport goroutines block here before reading speakerIP,
	// eliminating the race against FRR's initial Loc-RIB burst in active mode.
	// After the channel is closed, all subsequent receives are immediately non-blocking.
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
	adminHash string
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	// Store stop before spawning any goroutine.  The Go memory model guarantees
	// that all goroutines created inside the loop below observe this write.
	p.stopCh = stop
	for {
		select {
		case msg := <-queue:
			go p.producingWorker(msg)
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

func (p *producer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		p.producePeerMessage(peerUP, msg)
	case *bmp.PeerDownMessage:
		p.producePeerMessage(peerDown, msg)
	case *bmp.RouteMonitor:
		// Wait until PeerUp has populated speakerIP/speakerHash before producing
		// any route message.  In active mode (gobmp dials the router) FRR floods
		// its full Loc-RIB in a burst that races the PeerUp goroutine.  Blocking
		// here costs nothing after the channel is closed: a closed-channel receive
		// is a single no-op instruction with no lock or syscall involved.
		// The stopCh arm handles the case where the connection is terminated before
		// any PeerUp arrives, preventing these goroutines from leaking forever.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
			return
		}
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		// Same cancellable wait as RouteMonitor above.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
			return
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
		speakerReady:    make(chan struct{}),
	}
}
