package srpolicy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/tools"
)

// BSIDType defines type of BSID value
type BSIDType int

const (
	// NOBSID subtlv does not carry BSID
	NOBSID BSIDType = 1
	// LABELBSID subtlv carries Label as BSID
	LABELBSID BSIDType = 2
	// SRV6BSID subtlv carries SRv6 as BSID
	SRV6BSID BSIDType = 3
)

// BindingSID is an object carry the type of a specific Binding SID and the interface to get value
// the Binding SID
type BindingSID struct {
	Type BSIDType `json:"bsid_type,omitempty"`
	BSID BSID     `json:"bsid,omitempty"`
}

// UnmarshalJSON is custom Unmarshal fuction which will populate BSID interface with correct,
// depending on the BSID type value
func (bsid *BindingSID) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	// bsid_type is a mandatory field, if missing, then return error
	var bsidType BSIDType
	if err := json.Unmarshal(objmap["bsid_type"], &bsidType); err != nil {
		return err
	}
	var sid BSID
	switch bsidType {
	case NOBSID:
		sid = &noBSID{}
	case LABELBSID:
		sid = &labelBSID{}
	case SRV6BSID:
		sid = &srv6BSID{}
	default:
		return fmt.Errorf("unknown type of bsid %d", bsidType)
	}
	if b, ok := objmap["bsid"]; ok {
		if err := json.Unmarshal(b, &sid); err != nil {
			return err
		}
	}
	bsid.BSID = sid
	bsid.Type = bsidType

	return nil
}

// MarshalJSON is custom Marshaller which will generate a slice of bytes from BSID interface,
// depending on a bsid type.
func (bsid *BindingSID) MarshalJSON() ([]byte, error) {
	switch bsid.Type {
	case NOBSID:
		sid := &noBSID{
			flags: bsid.BSID.GetFlag(),
		}
		return json.Marshal(&struct {
			Type BSIDType `json:"bsid_type,omitempty"`
			BSID *noBSID  `json:"bsid,omitempty"`
		}{
			Type: bsid.Type,
			BSID: sid,
		})
	case LABELBSID:
		sid := &labelBSID{
			flags: bsid.BSID.GetFlag(),
			bsid:  binary.BigEndian.Uint32(bsid.BSID.GetBSID()),
		}
		return json.Marshal(&struct {
			Type BSIDType   `json:"bsid_type,omitempty"`
			BSID *labelBSID `json:"bsid,omitempty"`
		}{
			Type: bsid.Type,
			BSID: sid,
		})
	case SRV6BSID:
		sid := &srv6BSID{
			flags: bsid.BSID.GetFlag(),
			bsid:  bsid.BSID.GetBSID(),
		}
		return json.Marshal(&struct {
			Type BSIDType  `json:"bsid_type,omitempty"`
			BSID *srv6BSID `json:"bsid,omitempty"`
		}{
			Type: bsid.Type,
			BSID: sid,
		})
	default:
		return nil, fmt.Errorf("unknown type of bsid %d", bsid.Type)
	}
}

// BSID defines methods to get type and value of different types of Binding SID
type BSID interface {
	GetFlag() byte
	GetType() BSIDType
	GetBSID() []byte
	MarshalJSON() ([]byte, error)
}

// noBSID defines structure when Binding SID sub tlv carries no SID
type noBSID struct {
	flags byte
}

var _ BSID = &noBSID{}

func (n *noBSID) GetFlag() byte {
	return n.flags
}
func (n *noBSID) GetType() BSIDType {
	return NOBSID
}
func (n *noBSID) GetBSID() []byte {
	return nil
}

func (n *noBSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flags byte `json:"flags,omitempty"`
	}{
		Flags: n.flags,
	})
}

func (n *noBSID) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &n.flags); err != nil {
			return err
		}
	}

	return nil
}

// labelBSID defines structure when Binding SID sub tlv carries a label as Binding SID
type labelBSID struct {
	flags byte
	bsid  uint32
}

var _ BSID = &labelBSID{}

func (l *labelBSID) GetFlag() byte {
	return l.flags
}
func (l *labelBSID) GetType() BSIDType {
	return LABELBSID
}
func (l *labelBSID) GetBSID() []byte {
	bsid := make([]byte, 4)
	binary.BigEndian.PutUint32(bsid, l.bsid)
	return bsid
}

func (l *labelBSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flags byte   `json:"flags,omitempty"`
		BSID  uint32 `json:"label_bsid,omitempty"`
	}{
		Flags: l.flags,
		BSID:  l.bsid,
	})
}

func (l *labelBSID) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &l.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["label_bsid"]; ok {
		if err := json.Unmarshal(b, &l.bsid); err != nil {
			return err
		}
	}

	return nil
}

// SRv6BSID defines SRv6 BSID specific method
type SRv6BSID interface {
	GetEndpointBehavior() *srv6.EndpointBehavior
}

// srv6BSID defines structure when Binding SID sub tlv carries a srv6 as Binding SID
type srv6BSID struct {
	flags byte
	bsid  []byte
	eb    *srv6.EndpointBehavior
}

var _ BSID = &srv6BSID{}

func (s *srv6BSID) GetFlag() byte {
	return s.flags
}
func (s *srv6BSID) GetType() BSIDType {
	return SRV6BSID
}
func (s *srv6BSID) GetBSID() []byte {
	return s.bsid
}
func (s *srv6BSID) GetEndpointBehavior() *srv6.EndpointBehavior {
	return s.eb
}

func (s *srv6BSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flags byte   `json:"flags,omitempty"`
		BSID  []byte `json:"srv6_bsid,omitempty"`
	}{
		Flags: s.flags,
		BSID:  s.bsid,
	})
}

func (s *srv6BSID) UnmarshalJSON(b []byte) error {
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	if b, ok := objmap["flags"]; ok {
		if err := json.Unmarshal(b, &s.flags); err != nil {
			return err
		}
	}
	if b, ok := objmap["srv6_bsid"]; ok {
		if err := json.Unmarshal(b, &s.bsid); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalBSIDSTLV instantiates Binding SID object depending on
// the type and return BSID interface.
func UnmarshalBSIDSTLV(b []byte) (BSID, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Binding SID STLV Raw: %s", tools.MessageHex(b))
	}
	var bsid BSID
	p := 0
	switch len(b) {
	case 2:
		bsid = &noBSID{
			flags: b[p],
		}
	case 6:
		v := binary.BigEndian.Uint32(b[p+2 : p+2+4])
		v >>= 12
		bsid = &labelBSID{
			flags: b[p],
			bsid:  v,
		}
	case 18:
		sid := make([]byte, 16)
		copy(sid, b[p+2:p+2+16])
		bsid = &srv6BSID{
			flags: b[p],
			bsid:  sid,
		}
	default:
		return nil, fmt.Errorf("invalid length of binding sid stlv")
	}

	return bsid, nil
}
