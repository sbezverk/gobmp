package srpolicy

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// Preference sub-TLV is used to carry the preference of the SR
// Policy candidate path.  The contents of this sub-TLV are used by the
// SRPM.
type Preference struct {
	Flags      byte   `json:"flags,omitempty"`
	Preference uint32 `json:"preference,omitempty"`
}

// UnmarshalPreferenceSTLV build Preference object from a slice of bytes
func UnmarshalPreferenceSTLV(b []byte) (*Preference, error) {
	if glog.V(5) {
		glog.Infof("SR Policy Preference STLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) != 6 {
		return nil, fmt.Errorf("invalid length of preference stlv")
	}
	pref := &Preference{}
	p := 0
	pref.Flags = b[p]
	p++
	//Skip reserved byte
	p++
	pref.Preference = binary.BigEndian.Uint32(b[p : p+4])

	return pref, nil
}

// Weight sub-TLV specifies the weight associated to a given segment
// list.
type Weight struct {
	Flags  byte   `json:"flags,omitempty"`
	Weight uint32 `json:"weight,omitempty"`
}

// ENLP (Explicit NULL Label Policy) sub-TLV is used to indicate
// whether an Explicit NULL Label [RFC3032] must be pushed on an
// unlabeled IP packet before any other labels.
type ENLP struct {
	Flags byte `json:"flags,omitempty"`
	ENLP  byte `json:"enlp,omitempty"`
}

// Priority indicate the order
// in which the SR policies are re-computed upon topological change.
type Priority struct {
	Priority byte `json:"priority,omitempty"`
}

// PathName is used to attach a symbolic name to the SR Policy candidate path.
type PathName struct {
	PathName string `json:"path_name,omitempty"`
}

//PolicyName is a sub-TLV to associate a symbolic
// name with the SR Policy for which the candidate path is being
// advertised via the SR Policy NLRI.
type PolicyName struct {
	PolicyName string `json:"policy_name_name,omitempty"`
}
