package message

import (
	"testing"
)

// TestUnicastPrefixEqual_Symmetric verifies Equal() detects mismatches in both directions
// for boolean flags. Prior to this fix, Equal(a,b) could return true when Equal(b,a) returned false.
func TestUnicastPrefixEqual_Symmetric(t *testing.T) {
	tests := []struct {
		name string
		a, b UnicastPrefix
	}{
		{
			name: "IsIPv4 false vs true",
			a:    UnicastPrefix{IsIPv4: false},
			b:    UnicastPrefix{IsIPv4: true},
		},
		{
			name: "IsNexthopIPv4 false vs true",
			a:    UnicastPrefix{IsNexthopIPv4: false},
			b:    UnicastPrefix{IsNexthopIPv4: true},
		},
		{
			name: "IsAdjRIBInPost false vs true",
			a:    UnicastPrefix{IsAdjRIBInPost: false},
			b:    UnicastPrefix{IsAdjRIBInPost: true},
		},
		{
			name: "IsAdjRIBOutPost false vs true",
			a:    UnicastPrefix{IsAdjRIBOutPost: false},
			b:    UnicastPrefix{IsAdjRIBOutPost: true},
		},
		{
			name: "IsAdjRIBOut false vs true",
			a:    UnicastPrefix{IsAdjRIBOut: false},
			b:    UnicastPrefix{IsAdjRIBOut: true},
		},
		{
			name: "IsLocRIB false vs true",
			a:    UnicastPrefix{IsLocRIB: false},
			b:    UnicastPrefix{IsLocRIB: true},
		},
		{
			name: "IsLocRIBFiltered false vs true",
			a:    UnicastPrefix{IsLocRIBFiltered: false},
			b:    UnicastPrefix{IsLocRIBFiltered: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eq1, diffs1 := tt.a.Equal(&tt.b)
			eq2, diffs2 := tt.b.Equal(&tt.a)
			if eq1 {
				t.Errorf("a.Equal(b) = true, want false; diffs: %v", diffs1)
			}
			if eq2 {
				t.Errorf("b.Equal(a) = true, want false; diffs: %v", diffs2)
			}
			if len(diffs1) == 0 {
				t.Error("a.Equal(b) returned no diffs for mismatched values")
			}
			if len(diffs2) == 0 {
				t.Error("b.Equal(a) returned no diffs for mismatched values")
			}
		})
	}
}

// TestUnicastPrefixEqual_IdenticalFlags verifies Equal() returns true for identical boolean flags.
func TestUnicastPrefixEqual_IdenticalFlags(t *testing.T) {
	a := UnicastPrefix{
		IsIPv4:           true,
		IsNexthopIPv4:    true,
		IsAdjRIBInPost:   true,
		IsAdjRIBOutPost:  true,
		IsAdjRIBOut:      true,
		IsLocRIB:         true,
		IsLocRIBFiltered: true,
	}
	eq, diffs := a.Equal(&a)
	if !eq {
		t.Errorf("Equal() = false for identical values; diffs: %v", diffs)
	}
}

// TestUnicastPrefixEqual_Nil verifies Equal() handles nil receiver.
func TestUnicastPrefixEqual_Nil(t *testing.T) {
	a := UnicastPrefix{}
	eq, _ := a.Equal(nil)
	if eq {
		t.Error("Equal(nil) = true, want false")
	}
}

// TestUnicastPrefixEqual_TableName verifies Equal() detects TableName mismatches.
func TestUnicastPrefixEqual_TableName(t *testing.T) {
	a := UnicastPrefix{TableName: "VRF-A"}
	b := UnicastPrefix{TableName: "VRF-B"}
	c := UnicastPrefix{TableName: "VRF-A"}

	eq, diffs := a.Equal(&b)
	if eq {
		t.Error("Equal() = true for different TableName values")
	}
	if len(diffs) == 0 {
		t.Error("Equal() returned no diffs for different TableName values")
	}

	eq, _ = a.Equal(&c)
	if !eq {
		t.Error("Equal() = false for identical TableName values")
	}
}
