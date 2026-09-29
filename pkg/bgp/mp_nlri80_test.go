package bgp

import (
	"errors"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

func bgpLSSPFNodeNLRI(protocol base.ProtoID) []byte {
	descriptor := []byte{
		0x01, 0x00, 0x00, 0x10,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8,
		0x02, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
	}
	payload := append([]byte{byte(protocol)}, make([]byte, 8)...)
	payload = append(payload, descriptor...)
	return append([]byte{0x00, 0x01, 0x00, byte(len(payload))}, payload...)
}

func TestMPReachNLRIGetNLRI80(t *testing.T) {
	mp := &MPReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 80,
		NLRI:               bgpLSSPFNodeNLRI(base.Direct),
	}

	nlri, err := mp.GetNLRI80()
	if err != nil {
		t.Fatalf("GetNLRI80() unexpected error: %v", err)
	}
	if len(nlri.NLRI) != 1 {
		t.Fatalf("GetNLRI80() returned %d elements, want 1", len(nlri.NLRI))
	}
	node, ok := nlri.NLRI[0].LS.(*base.NodeNLRI)
	if !ok {
		t.Fatalf("GetNLRI80() element type = %T, want *base.NodeNLRI", nlri.NLRI[0].LS)
	}
	if node.ProtocolID != base.Direct || node.GetNodeASN() != 65000 {
		t.Errorf("GetNLRI80() decoded protocol/ASN = %d/%d, want %d/65000", node.ProtocolID, node.GetNodeASN(), base.Direct)
	}
	if got := node.LocalNode.GetBGPRouterID(); len(got) != 4 || got[3] != 1 {
		t.Errorf("GetNLRI80() BGP Router ID = %v, want 192.0.2.1", got)
	}
}

func TestMPReachNLRIGetNLRI80WithAddPath(t *testing.T) {
	pathID := []byte{0, 0, 0, 7}
	mp := &MPReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 80,
		NLRI:               append(pathID, bgpLSSPFNodeNLRI(base.Direct)...),
		addPath:            map[int]bool{80: true},
	}

	nlri, err := mp.GetNLRI80()
	if err != nil {
		t.Fatalf("GetNLRI80() with Add-Path unexpected error: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].PathID != 7 {
		t.Fatalf("GetNLRI80() Add-Path = %+v, want one element with path ID 7", nlri)
	}
}

func TestMPReachNLRIGetNLRI80RejectsOtherSAFI(t *testing.T) {
	mp := &MPReachNLRI{AddressFamilyID: 16388, SubAddressFamilyID: 71}
	_, err := mp.GetNLRI80()
	var notFound *NLRINotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("GetNLRI80() error = %T %v, want NLRINotFoundError", err, err)
	}
}

func TestMPUnReachNLRIGetNLRI80(t *testing.T) {
	mp := &MPUnReachNLRI{
		AddressFamilyID:    16388,
		SubAddressFamilyID: 80,
		WithdrawnRoutes:    bgpLSSPFNodeNLRI(base.Direct),
	}

	nlri, err := mp.GetNLRI80()
	if err != nil {
		t.Fatalf("GetNLRI80() unexpected error: %v", err)
	}
	if len(nlri.NLRI) != 1 || nlri.NLRI[0].Type != 1 {
		t.Fatalf("GetNLRI80() returned %+v, want one node NLRI", nlri)
	}
}

func TestMPUnReachNLRIGetNLRI80RejectsOtherSAFI(t *testing.T) {
	mp := &MPUnReachNLRI{AddressFamilyID: 16388, SubAddressFamilyID: 71}
	_, err := mp.GetNLRI80()
	var notFound *NLRINotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("GetNLRI80() error = %T %v, want NLRINotFoundError", err, err)
	}
}
