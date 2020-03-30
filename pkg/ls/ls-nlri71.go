package ls

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/tools"
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

// MarshalJSON defines a method to Marshal NLRI71 object into JSON format
func (ls *NLRI71) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	var t string
	var b []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Type\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", ls.Type))...)
	jsonData = append(jsonData, []byte("\"Description\":")...)
	switch ls.Type {
	case 1:
		t = "Node"
		n, err := base.UnmarshalNodeNLRI(ls.LS)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(&n)
		if err != nil {
			return nil, err
		}
	case 2:
		t = "Link"
		l, err := base.UnmarshalLinkNLRI(ls.LS)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(&l)
		if err != nil {
			return nil, err
		}
	case 3:
		t = "IPv4 Topology Prefix"
		n, err := base.UnmarshalPrefixNLRI(ls.LS)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(&n)
		if err != nil {
			return nil, err
		}
	case 4:
		t = "IPv6 Topology Prefix"
		n, err := base.UnmarshalPrefixNLRI(ls.LS)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(&n)
		if err != nil {
			return nil, err
		}
	case 6:
		t = "SRv6 SID"
		n, err := srv6.UnmarshalSRv6SIDNLRI(ls.LS)
		if err != nil {
			return nil, err
		}
		b, err = json.Marshal(&n)
		if err != nil {
			return nil, err
		}
	default:
		t = "Unknown"
		b = tools.RawBytesToJSON(ls.LS)
	}

	jsonData = append(jsonData, []byte(fmt.Sprintf("\"%s\",", t))...)
	jsonData = append(jsonData, []byte("\"LS\":")...)
	jsonData = append(jsonData, b...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
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
