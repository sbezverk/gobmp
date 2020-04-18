package ls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/tools"
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
		if n, err := base.UnmarshalPrefixNLRI(ls.LS, true); err == nil {
			nlri = n.String()
		} else {
			nlri = err.Error() + "\n"
		}
	case 4:
		t = "IPv6 Topology Prefix NLRI"
		if n, err := base.UnmarshalPrefixNLRI(ls.LS, false); err == nil {
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

// GetNodeNLRI instantiates Node NLRI object if one exists
func (ls *NLRI71) GetNodeNLRI() (*base.NodeNLRI, error) {
	if ls.Type != 1 {
		return nil, fmt.Errorf("not found")
	}
	n, err := base.UnmarshalNodeNLRI(ls.LS)
	if err != nil {
		return nil, err
	}

	return n, nil
}

// GetLinkNLRI instantiates Link NLRI object if one exists
func (ls *NLRI71) GetLinkNLRI() (*base.LinkNLRI, error) {
	if ls.Type != 2 {
		return nil, fmt.Errorf("not found")
	}
	l, err := base.UnmarshalLinkNLRI(ls.LS)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// GetPrefixNLRI instantiates IPv4 or IPv6 Prefix NLRI object if one exists
func (ls *NLRI71) GetPrefixNLRI(ipv4 bool) (*base.PrefixNLRI, error) {
	if ls.Type != 3 && ls.Type != 4 {
		return nil, fmt.Errorf("not found")
	}
	p, err := base.UnmarshalPrefixNLRI(ls.LS, ipv4)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// GetSRv6SIDNLRI instantiates SRv6 SID NLRI object if one exists
func (ls *NLRI71) GetSRv6SIDNLRI() (*srv6.SIDNLRI, error) {
	if ls.Type != 6 {
		return nil, fmt.Errorf("not found")
	}
	s, err := srv6.UnmarshalSRv6SIDNLRI(ls.LS)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// GetSubType return NLRI 71 subtype
func (ls *NLRI71) GetSubType() int {
	switch ls.Type {
	case 1:
		// Node NLRI
		return 32
	case 2:
		// Link NLRI
		return 33
	case 3:
		// IPv4 Topology Prefix NLRI
		return 34
	case 4:
		// IPv6 Topology Prefix NLRI
		return 35
	case 6:
		// SRv6 SID NLRI
		return 36
	}

	return 0
}

// UnmarshalLSNLRI71 builds Link State NLRI object ofor SAFI 71
func UnmarshalLSNLRI71(b []byte) (*NLRI71, error) {
	glog.V(6).Infof("LSNLRI71 Raw: %s", tools.MessageHex(b))
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
