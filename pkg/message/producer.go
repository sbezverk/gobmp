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
	publisher   pub.Publisher
	speakerIP   string
	speakerHash string
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
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
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
	}
}
