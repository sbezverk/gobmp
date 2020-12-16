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
	// UnicastPrefixV4Msg defines a subtype of BMP Route Monitoring message
	UnicastPrefixV4Msg = 74
	// UnicastPrefixV6Msg defines a subtype of BMP Route Monitoring message
	UnicastPrefixV6Msg = 76
	// LSNodeMsg defines a subtype of BMP Route Monitoring message
	LSNodeMsg = 8
	// LSLinkMsg defines a subtype of BMP Route Monitoring message
	LSLinkMsg = 9
	// PeerStateChangeMsg defines BMP Peer Up/Down message
	PeerStateChangeMsg = 10
	// L3VPNMsg defines BMP Peer Layer 3 VPN message
	L3VPNMsg = 11
	// L3VPNV4Msg defines BMP Peer Layer 3 VPN message
	L3VPNV4Msg = 114
	// L3VPNV6Msg defines BMP Peer Layer 3 VPN message
	L3VPNV6Msg = 116
	// LSPrefixMsg defines BMP Route Monitoring message carrying Prefix NLRI
	LSPrefixMsg = 12
	// LSSRv6SIDMsg defines BMP Route Monitoring message carrying SRv6 SID NLRI
	LSSRv6SIDMsg = 13
	// EVPNMsg defines BMP Route Monitoring message carrying EVPN NLRI
	EVPNMsg = 14
	// SRPolicyMsg defines a subtype of BMP Route Monitoring message for SR Policy NLRI
	SRPolicyMsg = 15
	// SRPolicyV4Msg defines a subtype of BMP Route Monitoring message for SR Policy NLRI AFI 1 SAFI 73
	SRPolicyV4Msg = 154
	// SRPolicyV6Msg defines a subtype of BMP Route Monitoring message for SR Policy NLRI AFI 2 SAFI 73
	SRPolicyV6Msg = 156
	// FlowspecMsg efines BMP Route Monitoring message carrying Flowspec NLRI
	FlowspecMsg = 16
	// FlowspecV4Msg defines BMP Route Monitoring message carrying Flowspec NLRI
	FlowspecV4Msg = 164
	// FlowspecV6Msg defines BMP Route Monitoring message carrying Flowspec NLRI
	FlowspecV6Msg = 166
)
