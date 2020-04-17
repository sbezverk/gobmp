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
	// LSNodeMsg defines a subtype of BMP Route Monitoring message
	LSNodeMsg = 8
	// LSLinkMsg defines a subtype of BMP Route Monitoring message
	LSLinkMsg = 9
	// PeerStateChangeMsg defines BMP Peer Up/Down message
	PeerStateChangeMsg = 10
	// L3VPNMsg defines BMP Peer Layer 3 VPN message
	L3VPNMsg = 11
	// LSPrefixMsg defines BMP Route Monitoring message carrying Prefix NLRI
	LSPrefixMsg = 12
	// LSSRv6SIDMsg defines BMP Route Monitoring message carrying SRv6 SID NLRI
	LSSRv6SIDMsg = 13
	// EVPNMsg defines BMP Route Monitoring message carrying EVPN NLRI
	EVPNMsg = 14
)
