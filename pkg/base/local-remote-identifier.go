package base

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocalRemoteIdentifierTLV defines Link Descriptor Local/Remote Identifiers TLV object
// RFC7752
type LocalRemoteIdentifierTLV struct {
	Local  []byte
	Remote []byte
}

func (lri *LocalRemoteIdentifierTLV) String() string {
	var s string
	s += "   Local/Remote Identifiers:" + "\n"
	s += fmt.Sprintf("      Local: %d\n", lri.Local)
	s += fmt.Sprintf("      Remote: %d\n", lri.Remote)

	return s
}

// GetLinkID return a string of a Local or Remote Link ID
func (lri *LocalRemoteIdentifierTLV) GetLinkID(local bool) string {
	if local {
		return net.IP(lri.Local).To4().String()
	}
	return net.IP(lri.Remote).To4().String()
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
