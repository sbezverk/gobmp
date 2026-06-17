package message

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
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
