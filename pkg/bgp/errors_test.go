package bgp

import (
	"errors"
	"testing"
)

func TestNLRINotFoundError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *NLRINotFoundError
		wantMsg string
	}{
		{
			name: "Error with type specified",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
				Type: "MP_REACH_NLRI",
			},
			wantMsg: "MP_REACH_NLRI not found for AFI 1 SAFI 1",
		},
		{
			name: "Error without type",
			err: &NLRINotFoundError{
				AFI:  2,
				SAFI: 128,
			},
			wantMsg: "NLRI not found for AFI 2 SAFI 128",
		},
		{
			name: "IPv6 unicast",
			err: &NLRINotFoundError{
				AFI:  2,
				SAFI: 1,
				Type: "MP_UNREACH_NLRI",
			},
			wantMsg: "MP_UNREACH_NLRI not found for AFI 2 SAFI 1",
		},
		{
			name: "L3VPN",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 128,
				Type: "MP_REACH_NLRI",
			},
			wantMsg: "MP_REACH_NLRI not found for AFI 1 SAFI 128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestNLRINotFoundError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name: "Same AFI and SAFI",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
				Type: "MP_REACH_NLRI",
			},
			target: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
			},
			want: true,
		},
		{
			name: "Different AFI",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
			},
			target: &NLRINotFoundError{
				AFI:  2,
				SAFI: 1,
			},
			want: false,
		},
		{
			name: "Different SAFI",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
			},
			target: &NLRINotFoundError{
				AFI:  1,
				SAFI: 128,
			},
			want: false,
		},
		{
			name: "Not an NLRINotFoundError",
			err: &NLRINotFoundError{
				AFI:  1,
				SAFI: 1,
			},
			target: errors.New("some other error"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewNLRINotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		afi      uint16
		safi     uint8
		nlriType string
		wantMsg  string
	}{
		{
			name:     "Create MP_REACH_NLRI error",
			afi:      1,
			safi:     1,
			nlriType: "MP_REACH_NLRI",
			wantMsg:  "MP_REACH_NLRI not found for AFI 1 SAFI 1",
		},
		{
			name:     "Create MP_UNREACH_NLRI error",
			afi:      2,
			safi:     128,
			nlriType: "MP_UNREACH_NLRI",
			wantMsg:  "MP_UNREACH_NLRI not found for AFI 2 SAFI 128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewNLRINotFoundError(tt.afi, tt.safi, tt.nlriType)
			if err.Error() != tt.wantMsg {
				t.Errorf("NewNLRINotFoundError() error = %v, want %v", err.Error(), tt.wantMsg)
			}

			// Verify it's the correct type
			var nlriErr *NLRINotFoundError
			if !errors.As(err, &nlriErr) {
				t.Error("NewNLRINotFoundError() did not return *NLRINotFoundError type")
			}

			// Verify fields
			if nlriErr.AFI != tt.afi {
				t.Errorf("AFI = %v, want %v", nlriErr.AFI, tt.afi)
			}
			if nlriErr.SAFI != tt.safi {
				t.Errorf("SAFI = %v, want %v", nlriErr.SAFI, tt.safi)
			}
			if nlriErr.Type != tt.nlriType {
				t.Errorf("Type = %v, want %v", nlriErr.Type, tt.nlriType)
			}
		})
	}
}

func TestErrorComparison(t *testing.T) {
	// Test that errors can be properly identified using errors.Is
	err := NewNLRINotFoundError(1, 1, "MP_REACH_NLRI")

	// Should match with same AFI/SAFI
	target := &NLRINotFoundError{AFI: 1, SAFI: 1}
	if !errors.Is(err, target) {
		t.Error("Expected errors.Is to return true for matching AFI/SAFI")
	}

	// Should not match with different AFI/SAFI
	target2 := &NLRINotFoundError{AFI: 2, SAFI: 1}
	if errors.Is(err, target2) {
		t.Error("Expected errors.Is to return false for different AFI/SAFI")
	}
}

func TestAttributeNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *AttributeNotFoundError
		wantMsg string
	}{
		{
			name: "Error with attribute name",
			err: &AttributeNotFoundError{
				AttributeType: 29,
				AttributeName: "BGP-LS",
			},
			wantMsg: "BGP attribute BGP-LS (type 29) not found",
		},
		{
			name: "Error without attribute name",
			err: &AttributeNotFoundError{
				AttributeType: 40,
			},
			wantMsg: "BGP attribute type 40 not found",
		},
		{
			name: "Prefix SID attribute",
			err: &AttributeNotFoundError{
				AttributeType: 40,
				AttributeName: "Prefix SID",
			},
			wantMsg: "BGP attribute Prefix SID (type 40) not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %v, want %v", got, tt.wantMsg)
			}
		})
	}
}

func TestAttributeNotFoundError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name: "Same attribute type",
			err: &AttributeNotFoundError{
				AttributeType: 29,
				AttributeName: "BGP-LS",
			},
			target: &AttributeNotFoundError{
				AttributeType: 29,
			},
			want: true,
		},
		{
			name: "Different attribute type",
			err: &AttributeNotFoundError{
				AttributeType: 29,
			},
			target: &AttributeNotFoundError{
				AttributeType: 40,
			},
			want: false,
		},
		{
			name: "Not an AttributeNotFoundError",
			err: &AttributeNotFoundError{
				AttributeType: 29,
			},
			target: errors.New("some other error"),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Errorf("errors.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAttributeNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		attrType uint8
		attrName string
		wantMsg  string
	}{
		{
			name:     "Create BGP-LS attribute error",
			attrType: 29,
			attrName: "BGP-LS",
			wantMsg:  "BGP attribute BGP-LS (type 29) not found",
		},
		{
			name:     "Create Prefix SID attribute error",
			attrType: 40,
			attrName: "Prefix SID",
			wantMsg:  "BGP attribute Prefix SID (type 40) not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAttributeNotFoundError(tt.attrType, tt.attrName)
			if err.Error() != tt.wantMsg {
				t.Errorf("NewAttributeNotFoundError() error = %v, want %v", err.Error(), tt.wantMsg)
			}

			// Verify it's the correct type
			var attrErr *AttributeNotFoundError
			if !errors.As(err, &attrErr) {
				t.Error("NewAttributeNotFoundError() did not return *AttributeNotFoundError type")
			}

			// Verify fields
			if attrErr.AttributeType != tt.attrType {
				t.Errorf("AttributeType = %v, want %v", attrErr.AttributeType, tt.attrType)
			}
			if attrErr.AttributeName != tt.attrName {
				t.Errorf("AttributeName = %v, want %v", attrErr.AttributeName, tt.attrName)
			}
		})
	}
}
