package bgp

import "fmt"

// NLRINotFoundError indicates that NLRI for a specific AFI/SAFI combination was not found
type NLRINotFoundError struct {
	AFI  uint16
	SAFI uint8
	Type string // "MP_REACH_NLRI", "MP_UNREACH_NLRI", or "UPDATE"
}

// Error implements the error interface
func (e *NLRINotFoundError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("%s not found for AFI %d SAFI %d", e.Type, e.AFI, e.SAFI)
	}
	return fmt.Sprintf("NLRI not found for AFI %d SAFI %d", e.AFI, e.SAFI)
}

// Is allows error comparison using errors.Is
func (e *NLRINotFoundError) Is(target error) bool {
	t, ok := target.(*NLRINotFoundError)
	if !ok {
		return false
	}
	// Match if AFI and SAFI are the same (Type is optional for matching)
	return e.AFI == t.AFI && e.SAFI == t.SAFI
}

// Common error variables for specific cases
var (
	// ErrNLRINotFound is a generic NLRI not found error
	ErrNLRINotFound = &NLRINotFoundError{}
)

// NewNLRINotFoundError creates a new NLRINotFoundError with context
func NewNLRINotFoundError(afi uint16, safi uint8, nlriType string) error {
	return &NLRINotFoundError{
		AFI:  afi,
		SAFI: safi,
		Type: nlriType,
	}
}

// AttributeNotFoundError indicates that a BGP attribute was not found in the update
type AttributeNotFoundError struct {
	AttributeType uint8
	AttributeName string
}

// Error implements the error interface
func (e *AttributeNotFoundError) Error() string {
	if e.AttributeName != "" {
		return fmt.Sprintf("BGP attribute %s (type %d) not found", e.AttributeName, e.AttributeType)
	}
	return fmt.Sprintf("BGP attribute type %d not found", e.AttributeType)
}

// Is allows error comparison using errors.Is
func (e *AttributeNotFoundError) Is(target error) bool {
	t, ok := target.(*AttributeNotFoundError)
	if !ok {
		return false
	}
	return e.AttributeType == t.AttributeType
}

// Common attribute error variables
var (
	// ErrAttributeNotFound is a generic attribute not found error
	ErrAttributeNotFound = &AttributeNotFoundError{}
)

// NewAttributeNotFoundError creates a new AttributeNotFoundError with context
func NewAttributeNotFoundError(attrType uint8, attrName string) error {
	return &AttributeNotFoundError{
		AttributeType: attrType,
		AttributeName: attrName,
	}
}
