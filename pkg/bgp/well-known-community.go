package bgp

// wellKnownCommunities maps 32-bit BGP COMMUNITIES attribute (RFC 1997) values
// to their symbolic names. Names are verbatim from the IANA "Border Gateway
// Protocol (BGP) Well-known Communities" registry. Only values with a stable
// (RFC) specification reference are included; draft-only code points
// (0xFFFF0002-0xFFFF0005, 0xFFFF0008) are intentionally omitted.
var wellKnownCommunities = map[uint32]string{
	0xFFFF0000: "GRACEFUL_SHUTDOWN",   // RFC 8326 §2
	0xFFFF0001: "ACCEPT_OWN",          // RFC 7611 §4
	0xFFFF0006: "LLGR_STALE",          // RFC 9494 §4.2
	0xFFFF0007: "NO_LLGR",             // RFC 9494 §4.2
	0xFFFF0009: "Standby PE",          // RFC 9026 §5
	0xFFFF029A: "BLACKHOLE",           // RFC 7999 §5
	0xFFFFFF01: "NO_EXPORT",           // RFC 1997
	0xFFFFFF02: "NO_ADVERTISE",        // RFC 1997
	0xFFFFFF03: "NO_EXPORT_SUBCONFED", // RFC 1997
	0xFFFFFF04: "NOPEER",              // RFC 3765 §4
}

// unmarshalWellKnownCommunity returns the IANA-registered symbolic names for any
// well-known communities (RFC 1997 and related) carried in the COMMUNITIES
// attribute value b. Names are returned in wire order, preserving duplicates so
// the result mirrors CommunityList. It returns nil when b carries no recognized
// well-known community.
func unmarshalWellKnownCommunity(b []byte) []string {
	var names []string
	for _, c := range getCommunity(b) {
		if name, ok := wellKnownCommunities[c]; ok {
			names = append(names, name)
		}
	}

	return names
}
