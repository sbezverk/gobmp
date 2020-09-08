package base

import (
	"encoding/binary"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocalRemoteIdentifierTLV defines Link Descriptor Local/Remote Identifiers TLV object
// RFC7752
type LocalRemoteIdentifierTLV struct {
	Local  []byte
	Remote []byte
}

// GetLinkID return a string of a Local or Remote Link ID
func (lri *LocalRemoteIdentifierTLV) GetLinkID(local bool) uint32 {
	if local {
		return binary.BigEndian.Uint32(lri.Local)
	}
	return binary.BigEndian.Uint32(lri.Remote)
}

// UnmarshalLocalRemoteIdentifierTLV builds Link Descriptor Local/Remote Identifiers TLV object
func UnmarshalLocalRemoteIdentifierTLV(b []byte) (*LocalRemoteIdentifierTLV, error) {
	glog.V(6).Infof("LocalRemoteIdentifierTLV Raw: %s", tools.MessageHex(b))
	l := make([]byte, 4)
	copy(l, b[:4])
	r := make([]byte, 4)
	copy(r, b[4:])
	lri := LocalRemoteIdentifierTLV{
		Local:  l,
		Remote: r,
	}

	return &lri, nil
}
