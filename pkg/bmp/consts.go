package bmp

const (
	// CommonHeaderLength defines the length of BMP's Common header
	CommonHeaderLength = 6
	// PerPeerHeaderLength defines the length of BMP's Per Peer Header
	PerPeerHeaderLength = 42

	// RouteMonitor defines BMP Route Monitor message type
	RouteMonitor = 0
	// StatsReport defines BMP Statistics Report message
	StatsReport = 1
	// PeerDown defines BMP Peer Down message
	PeerDown = 2
	// PeerUp defines BMP Peer Up message
	PeerUp = 3
	// Initiation defines BMP Initiation message
	Initiation = 4
	// Termination defines BMP Termination message
	Termination = 5
	// RouteMirror defines BMP Route Mirror message type
	RouteMirror = 6
)
