package message

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"

	"github.com/sbezverk/gobmp/pkg/mup"
)

func ensureMessageHash(msg any) {
	switch m := msg.(type) {
	case *PeerStateChange:
		setPeerStateChangeHash(m)
	case **PeerStateChange:
		if m != nil {
			setPeerStateChangeHash(*m)
		}
	case *UnicastPrefix:
		setUnicastPrefixHash(m)
	case **UnicastPrefix:
		if m != nil {
			setUnicastPrefixHash(*m)
		}
	case *L3VPNPrefix:
		setL3VPNPrefixHash(m)
	case **L3VPNPrefix:
		if m != nil {
			setL3VPNPrefixHash(*m)
		}
	case *MUPPrefix:
		setMUPPrefixHash(m)
	case **MUPPrefix:
		if m != nil {
			setMUPPrefixHash(*m)
		}
	}
}

func setPeerStateChangeHash(m *PeerStateChange) {
	if m == nil || m.Hash != "" {
		return
	}
	m.Hash = hashParts(
		"peer",
		m.RouterHash,
		m.RemoteBGPID,
		m.RemoteIP,
		strconv.FormatUint(uint64(m.RemoteASN), 10),
		strconv.FormatUint(uint64(m.PeerType), 10),
		m.PeerRD,
	)
}

func setUnicastPrefixHash(m *UnicastPrefix) {
	if m == nil || m.Hash != "" || m.IsEOR {
		return
	}
	m.Hash = hashParts(
		"unicast",
		m.RouterHash,
		m.PeerHash,
		m.Prefix,
		strconv.FormatInt(int64(m.PrefixLen), 10),
		strconv.FormatBool(m.IsIPv4),
		strconv.FormatInt(int64(m.PathID), 10),
		labelsHashPart(m.Labels),
	)
}

func setL3VPNPrefixHash(m *L3VPNPrefix) {
	if m == nil || m.Hash != "" || m.IsEOR {
		return
	}
	m.Hash = hashParts(
		"l3vpn",
		m.RouterHash,
		m.PeerHash,
		m.VPNRD,
		strconv.FormatUint(uint64(m.VPNRDType), 10),
		m.Prefix,
		strconv.FormatInt(int64(m.PrefixLen), 10),
		strconv.FormatBool(m.IsIPv4),
		strconv.FormatInt(int64(m.PathID), 10),
		labelsHashPart(m.Labels),
	)
}

// setMUPPrefixHash hashes the route key of draft-ietf-bess-mup-safi-01, which
// differs per route type: RD, Prefix Length and Prefix for Interwork Segment
// Discovery (Section 3.1.1) and Type 1 ST (Section 3.1.3), RD and Address for
// Direct Segment Discovery (Section 3.1.2), RD, Endpoint Address and the
// Architecture specific Endpoint Identifier for Type 2 ST (Section 3.1.4).
// The TEID is a variable length identifier, so its length, carried by the
// Endpoint Length, is part of its identity. Forwarding attributes such as the
// ST1 TEID, QFI, source address and TLVs are not part of the key, a withdraw
// carries the key alone and must hash the same as the announcement.
func setMUPPrefixHash(m *MUPPrefix) {
	if m == nil || m.Hash != "" || m.IsEOR {
		return
	}
	parts := []string{
		"mup",
		m.RouterHash,
		m.PeerHash,
		m.VPNRD,
		strconv.FormatUint(uint64(m.VPNRDType), 10),
		strconv.FormatUint(uint64(m.ArchType), 10),
		strconv.FormatUint(uint64(m.RouteType), 10),
		strconv.FormatBool(m.IsIPv4),
		strconv.FormatInt(int64(m.PathID), 10),
	}
	switch m.RouteType {
	case mup.RouteTypeISD, mup.RouteTypeST1:
		parts = append(parts, m.Prefix, strconv.FormatUint(uint64(m.PrefixLen), 10))
	case mup.RouteTypeDSD:
		parts = append(parts, m.Address)
	case mup.RouteTypeST2:
		teid := ""
		if m.TEID != nil {
			teid = strconv.FormatUint(uint64(*m.TEID), 10)
		}
		parts = append(parts, m.EndpointAddress, strconv.FormatUint(uint64(m.EndpointLen), 10), teid)
	}
	m.Hash = hashParts(parts...)
}

func labelsHashPart(labels []uint32) string {
	if len(labels) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(labels)*12)
	for i, label := range labels {
		if i != 0 {
			buf = append(buf, ',')
		}
		buf = strconv.AppendUint(buf, uint64(label), 10)
	}
	return string(buf)
}

func hashParts(parts ...string) string {
	h := md5.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
