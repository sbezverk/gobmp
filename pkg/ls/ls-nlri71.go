package ls

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/te"
	"github.com/sbezverk/tools"
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

// UnmarshalLSNLRI71 builds Link State NLRI object for SAFI 71
func UnmarshalLSNLRI71(b []byte) (*NLRI71, error) {
	if glog.V(6) {
		glog.Infof("LSNLRI71 Raw: %s ", tools.MessageHex(b))
	}
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
		case 2:
			n, err := base.UnmarshalLinkNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 3:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], true)
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 4:
			n, err := base.UnmarshalPrefixNLRI(b[p:p+int(el.Length)], false)
			if err != nil {
				return nil, err
			}
			el.LS = n
			// TODO (sbezverk)
			// https://tools.ietf.org/html/draft-ietf-idr-te-lsp-distribution-14#ref-I-D.ietf-spring-segment-routing-policy
		case 5:
			n, err := te.UnmarshalTEPolicyNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
		case 6:
			n, err := srv6.UnmarshalSRv6SIDNLRI(b[p : p+int(el.Length)])
			if err != nil {
				return nil, err
			}
			el.LS = n
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
