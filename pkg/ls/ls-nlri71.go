package ls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Element defines a generic NLRI object carried in NLRI type 71,
// the type of the object will be used to cast it into a corresponding to a specific type structure.
type Element struct {
	Type   uint16
	Length uint16 // Not including Type and itself
	LS     interface{}
}

// NLRI71 defines Link State NLRI object for SAFI 71
// https://tools.ietf.org/html/rfc7752#section-3.2
type NLRI71 struct {
	Type   uint16
	Length uint16 // Not including Type and itself
	LS     []byte
	NLRI   []Element
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

// UnmarshalLSNLRI71 builds Link State NLRI object ofor SAFI 71
func UnmarshalLSNLRI71(b []byte) (*NLRI71, error) {
	glog.V(6).Infof("LSNLRI71 Raw: %s ", tools.MessageHex(b))
	if len(b) == 0 {
		return nil, fmt.Errorf("NLRI length is 0")
	}
	ls := NLRI71{
		NLRI: make([]Element, 0),
	}
	for p := 0; p < len(b); {
		el := Element{}
		el.Type = binary.BigEndian.Uint16(b[p : p+2])
		p += 2
		el.Length = binary.BigEndian.Uint16(b[p : p+2])
		p += 2

		switch el.Type {
		case 1:
			n, err := base.UnmarshalNodeNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
			//			r, _ := json.Marshal(n)
			//			glog.Infof(" ><SB> Node NLRI v6: %s", string(r))
		case 2:
			n, err := base.UnmarshalLinkNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
			//			r, _ := json.Marshal(n)
			//			glog.Infof(" ><SB> Link NLRI v6: %s", string(r))
		case 3:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], true)
			if err != nil {
				return nil, err
			}
			el.LS = n
			//			r, _ := json.Marshal(n)
			//			glog.Infof(" ><SB> Prefix NLRI v4: %s", string(r))
		case 4:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], false)
			if err != nil {
				return nil, err
			}
			el.LS = n
			//			r, _ := json.Marshal(n)
			//			glog.Infof(" ><SB> Prefix NLRI v6: %s", string(r))
		case 6:
			n, err := srv6.UnmarshalSRv6SIDNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
			//			r, _ := json.Marshal(n)
			//			glog.Infof(" ><SB> SID NLRI v6: %s", string(r))
		default:
			el.LS = make([]byte, el.Length)
			if p+int(el.Length) <= len(b) {
				copy(el.LS.([]byte), b[p:p+int(el.Length)])
			} else {
				copy(el.LS.([]byte), b[p:])
			}
		}
		if p+int(el.Length) <= len(b) {
			p += int(el.Length)
		} else {
			p = len(b)
		}

		ls.NLRI = append(ls.NLRI, el)
	}

	return &ls, nil
}
