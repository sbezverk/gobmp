package ls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/internal"
	"github.com/sbezverk/gobmp/pkg/srv6"
)

// NLRI71 defines Link State NLRI object for SAFI 71
// https://tools.ietf.org/html/rfc7752#section-3.2
type NLRI71 struct {
	Type   uint16
	Length uint16 // Not including Type and itself
	LS     []byte
}

func (ls *NLRI71) String() string {
	var s, t, nlri string
	switch ls.Type {
	case 1:
		t = "Node NLRI"
		if n, err := base.UnmarshalNodeNLRI(ls.LS); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	case 2:
		t = "Link NLRI"
		if n, err := base.UnmarshalLinkNLRI(ls.LS); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	case 3:
		t = "IPv4 Topology Prefix NLRI"
		if n, err := base.UnmarshalPrefixNLRI(ls.LS); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	case 4:
		t = "IPv6 Topology Prefix NLRI"
		if n, err := base.UnmarshalPrefixNLRI(ls.LS); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	case 6:
		t = "SRv6 SID NLRI"
		if n, err := srv6.UnmarshalSRv6SIDNLRI(ls.LS); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	default:
		t = "Unknown NLRI"
	}
	s += fmt.Sprintf("NLRI Type: %s\n", t)
	s += fmt.Sprintf("Total NLRI Length: %d\n", ls.Length)
	s += nlri

	return s
}

// UnmarshalLSNLRI71 builds Link State NLRI object ofor SAFI 71
func UnmarshalLSNLRI71(b []byte) (*NLRI71, error) {
	glog.V(6).Infof("LSNLRI71 Raw: %s", internal.MessageHex(b))
	ls := NLRI71{}
	p := 0
	ls.Type = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	ls.Length = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	switch ls.Type {
	case 1:
		// Node NLRI
	case 2:
		// Link NLRI
	case 3:
		// IPv4 Topology Prefix NLRI
	case 4:
		// IPv6 Topology Prefix NLRI
	case 6:
		// SRv6 SID NLRI
	default:
		return nil, fmt.Errorf("invalid LS NLRI type %d", ls.Type)
	}
	ls.LS = b[p : p+int(ls.Length)]

	return &ls, nil
}
