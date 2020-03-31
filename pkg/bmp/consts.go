package bmp

const (
	// CommonHeaderLength defines the length of BMP's Common header
	CommonHeaderLength = 6
	// PerPeerHeaderLength defines the length of BMP's Per Peer Header
	PerPeerHeaderLength = 42

	// RouteMonitorMsg defines BMP Route Monitor message type
	RouteMonitorMsg = 0
	// StatsReportMsg defines BMP Statistics Report message
	StatsReportMsg = 1
	// PeerDownMsg defines BMP Peer Down message
	PeerDownMsg = 2
	// PeerUpMsg defines BMP Peer Up message
	PeerUpMsg = 3
	// InitiationMsg defines BMP Initiation message
	InitiationMsg = 4
	// TerminationMsg defines BMP Termination message
	TerminationMsg = 5
	// RouteMirrorMsg defines BMP Route Mirror message type
	RouteMirrorMsg = 6
	// UnicastPrefixMsg defines a subtype of BMP Route Monitoring message
	UnicastPrefixMsg = 7
)
