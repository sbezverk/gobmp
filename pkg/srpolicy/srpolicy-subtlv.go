package srpolicy

// Preference sub-TLV is used to carry the preference of the SR
// Policy candidate path.  The contents of this sub-TLV are used by the
// SRPM.
type Preference struct {
	Flags      byte   `json:"flags,omitempty"`
	Preference uint32 `json:"preference,omitempty"`
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
