package base

import (
	"testing"
)

func TestUnmarshalMultiTopologyIdentifierTLV(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
		want    []*MultiTopologyIdentifier
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "odd-length input",
			input:   []byte{0x0f, 0xff, 0x01}, // 3 bytes — not divisible by 2
			wantErr: true,
		},
		{
			name: "two valid entries",
			// Entry 1: 0x8FFF → OFlag=true,  AFlag=false, MTID=0x0FFF
			// Entry 2: 0x4001 → OFlag=false, AFlag=true,  MTID=0x0001
			input:   []byte{0x8f, 0xff, 0x40, 0x01},
			wantErr: false,
			want: []*MultiTopologyIdentifier{
				{OFlag: true, AFlag: false, MTID: 0x0fff},
				{OFlag: false, AFlag: true, MTID: 0x0001},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMultiTopologyIdentifierTLV(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalMultiTopologyIdentifierTLV() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(tt.want))
			}
			for i, w := range tt.want {
				g := got[i]
				if g.OFlag != w.OFlag || g.AFlag != w.AFlag || g.MTID != w.MTID {
					t.Errorf("entry[%d]: got {OFlag:%v AFlag:%v MTID:0x%04x}, want {OFlag:%v AFlag:%v MTID:0x%04x}",
						i, g.OFlag, g.AFlag, g.MTID, w.OFlag, w.AFlag, w.MTID)
				}
			}
		})
	}
}
