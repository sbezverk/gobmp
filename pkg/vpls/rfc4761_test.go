package vpls

import "testing"

func TestGetLabelRange_ZeroBlockSize(t *testing.T) {
	zero := uint16(0)
	base := uint32(100)
	n := &NLRI{
		RFCType:     "RFC4761",
		LabelBase:   &base,
		VEBlockSize: &zero,
	}
	start, end := n.GetLabelRange()
	if start != 0 || end != 0 {
		t.Errorf("zero VEBlockSize: got (%d, %d), want (0, 0)", start, end)
	}
}

func TestGetLabelRange_NonZeroBlockSize(t *testing.T) {
	size := uint16(10)
	base := uint32(100)
	n := &NLRI{
		RFCType:     "RFC4761",
		LabelBase:   &base,
		VEBlockSize: &size,
	}
	start, end := n.GetLabelRange()
	if start != 100 || end != 109 {
		t.Errorf("got (%d, %d), want (100, 109)", start, end)
	}
}

func TestGetLabelRange_NotRFC4761(t *testing.T) {
	n := &NLRI{RFCType: "RFC6074"}
	start, end := n.GetLabelRange()
	if start != 0 || end != 0 {
		t.Errorf("non-RFC4761: got (%d, %d), want (0, 0)", start, end)
	}
}
