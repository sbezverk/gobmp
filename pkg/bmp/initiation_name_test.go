package bmp

import "testing"

func TestInitiationSysNameDescr(t *testing.T) {
	tests := []struct {
		name      string
		tlvs      []InformationalTLV
		wantName  string
		wantDescr string
	}{
		{name: "no TLVs"},
		{
			name: "both present",
			tlvs: []InformationalTLV{
				{InformationType: 1, Information: []byte("Arista vEOS")},
				{InformationType: 2, Information: []byte("switch1")},
			},
			wantName:  "switch1",
			wantDescr: "Arista vEOS",
		},
		{
			name:     "only sysName, other types ignored",
			tlvs:     []InformationalTLV{{InformationType: 0, Information: []byte("free")}, {InformationType: 2, Information: []byte("switch1")}},
			wantName: "switch1",
		},
		{
			name:     "first of repeated TLVs wins",
			tlvs:     []InformationalTLV{{InformationType: 2, Information: []byte("a")}, {InformationType: 2, Information: []byte("b")}},
			wantName: "a",
		},
		{
			name: "empty string TLV",
			tlvs: []InformationalTLV{{InformationType: 2}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &InitiationMessage{TLV: tt.tlvs}
			if got := m.SysName(); got != tt.wantName {
				t.Errorf("SysName() = %q, want %q", got, tt.wantName)
			}
			if got := m.SysDescr(); got != tt.wantDescr {
				t.Errorf("SysDescr() = %q, want %q", got, tt.wantDescr)
			}
		})
	}
}

func TestInitiationSysNameDescrNil(t *testing.T) {
	var m *InitiationMessage
	if got := m.SysName(); got != "" {
		t.Errorf("SysName() on nil = %q, want empty", got)
	}
	if got := m.SysDescr(); got != "" {
		t.Errorf("SysDescr() on nil = %q, want empty", got)
	}
}
