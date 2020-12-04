package bgpls

type TEPolicyStateObjects interface {
}

// ObjectOriginType defines the component (or protocol) from which the contained object originated.
type ObjectOriginType uint8

const (
	// RSVPTE defines RSVP-TE as an originating protocol
	RSVPTE ObjectOriginType = 1
	// PCEP defines PCEP as an originating protocol
	PCEP ObjectOriginType = 2
	// Local  defines Local or Static as originating protocol
	Local ObjectOriginType = 3
)

type MPLSTEPolicyStateAddressFamilyType uint8

const (
	MPLSIPV4 MPLSTEPolicyStateAddressFamilyType = 1
	MPLSIPV6 MPLSTEPolicyStateAddressFamilyType = 2
)

type MPLSTEPolicyState struct {
	ObjectOrigin  ObjectOriginType                   `json:"object_origin,omitempty"`
	AddressFamily MPLSTEPolicyStateAddressFamilyType `json:"address_family,omitempty"`
	StateObjects  []TEPolicyStateObjects             ` json:"te_policy_state_objects,omitempty"`
}
