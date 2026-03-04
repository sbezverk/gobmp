package base

import (
	"reflect"
	"strings"
	"testing"
)

func TestLabelString(t *testing.T) {
	l := &Label{Value: 100, Exp: 2, BoS: true}
	got := l.String()
	if got == "" {
		t.Error("Label.String() returned empty string")
	}
	// Check it contains the value
	if !strings.Contains(got, "100") {
		t.Errorf("Label.String() = %q, expected to contain \"100\"", got)
	}
}

func TestLabelGetRawValue(t *testing.T) {
	// Value=1 Exp=0 BoS=true → raw = 1*16 + 0*2 + 1 = 17
	l := &Label{Value: 1, Exp: 0, BoS: true}
	if got := l.GetRawValue(); got != 17 {
		t.Errorf("GetRawValue() = %d, want 17", got)
	}
	// Value=1 Exp=0 BoS=false → raw = 16
	l2 := &Label{Value: 1, Exp: 0, BoS: false}
	if got := l2.GetRawValue(); got != 16 {
		t.Errorf("GetRawValue() = %d, want 16", got)
	}
}

func TestMakeLabel(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect *Label
		fail   bool
	}{
		{
			name:  "label 1",
			input: []byte{5, 220, 33},
			expect: &Label{
				Value: 24002,
				Exp:   0,
				BoS:   true,
			},
			fail: false,
		},
		{
			name:  "label 2",
			input: []byte{5, 220, 65},
			expect: &Label{
				Value: 24004,
				Exp:   0,
				BoS:   true,
			},
			fail: false,
		},
		{
			name:   "wrong length",
			input:  []byte{5, 220, 33, 0},
			expect: nil,
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeLabel(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if err == nil {
				if !reflect.DeepEqual(got, tt.expect) {
					t.Errorf("Expected label %+v does not match to actual label %+v", got, *tt.expect)
				}
			}
		})
	}
}

func TestMakeRD(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
		fail   bool
	}{
		{
			name:   "rd type 0",
			input:  []byte{0, 0, 2, 65, 0, 0, 253, 234},
			expect: "577:65002",
			fail:   false,
		},
		{
			name:   "rd type 1",
			input:  []byte{0, 1, 2, 65, 0, 0, 253, 234},
			expect: "2.65.0.0:65002",
			fail:   false,
		},
		{
			name:   "rd type 2",
			input:  []byte{0, 2, 2, 65, 0, 0, 253, 234},
			expect: "37814272:65002",
			fail:   false,
		},
		{
			name:   "wrong length",
			input:  []byte{0, 0, 2, 65, 0, 0, 253, 234, 1},
			expect: "",
			fail:   true,
		},
		{
			name:   "invalid rd type",
			input:  []byte{0, 3, 2, 65, 0, 0, 253, 234, 1},
			expect: "",
			fail:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MakeRD(tt.input)
			if err != nil && !tt.fail {
				t.Fatalf("expected to succeed but failed with error: %+v", err)
			}
			if err == nil && tt.fail {
				t.Fatalf("expected to fail but succeeded")
			}
			if err == nil {
				if strings.Compare(got.String(), tt.expect) != 0 {
					t.Errorf("Expected label %s does not match to actual label %s", got.String(), tt.expect)
				}
			}
		})
	}
}
