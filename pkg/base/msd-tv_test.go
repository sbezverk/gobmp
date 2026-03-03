package base

import "testing"

func TestUnmarshalMSDTV(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		want    []*MSDTV
		wantErr bool
	}{
		{
			name:    "Empty input",
			b:       []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Odd inoput length",
			b:       []byte{0x01, 0x02, 0x03},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test UnmarshalMSDTV",
			b:    []byte{0x01, 0x02, 0x03, 0x04},
			want: []*MSDTV{
				{Type: 0x01, Value: 0x02},
				{Type: 0x03, Value: 0x04},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalMSDTV(tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalMSDTV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !equalMSDTVSlices(got, tt.want) {
				t.Errorf("UnmarshalMSDTV() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func equalMSDTVSlices(a, b []*MSDTV) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}
