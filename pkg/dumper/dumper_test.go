package dumper

import (
	"bytes"
	"encoding/json"
	"log"
	"reflect"
	"testing"
)

func TestMessageAsValidJSON(t *testing.T) {
	tests := []struct {
		name    string
		msgOut  msgOut
		wantErr bool
	}{
		{
			name: "test1",
			msgOut: msgOut{
				MsgType: 0,
				MsgHash: "hash1",
				Msg:     []byte(`{"field1":"value1","field2":2}`),
			},
			wantErr: false,
		},
		{
			name: "test2",
			msgOut: msgOut{
				MsgType: 1,
				MsgHash: "hash2",
				Msg:     []byte(`{"field1":"value1","field2":2}`),
			},
			wantErr: false,
		},
		{
			name: "test3 invalid JSON",
			msgOut: msgOut{
				MsgType: 1,
				MsgHash: "hash2",
				Msg:     []byte(`{"field1":"value1","field2:2}`),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buff := new(bytes.Buffer)
			pw := pubwriter{
				output: log.New(buff, "", 0),
			}
			err := pw.PublishMessage(tt.msgOut.MsgType, []byte(tt.msgOut.MsgHash), tt.msgOut.Msg)
			if (err != nil) && !tt.wantErr {
				t.Errorf("PublishMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
			if (err == nil) && tt.wantErr {
				t.Errorf("PublishMessage() expected error but got none, wantErr %v", tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			var got msgOut
			err = json.Unmarshal(buff.Bytes(), &got)
			if err != nil {
				t.Errorf("Failed to unmarshal msgOut: %v", err)
			}
			if tt.msgOut.MsgType != got.MsgType {
				t.Errorf("MsgType mismatch: expected %d, got %d", tt.msgOut.MsgType, got.MsgType)
			}
			if tt.msgOut.MsgHash != got.MsgHash {
				t.Errorf("MsgHash mismatch: expected %s, got %s", tt.msgOut.MsgHash, got.MsgHash)
			}
			var expectedMsg any
			if err := json.Unmarshal(tt.msgOut.Msg, &expectedMsg); err != nil {
				t.Fatalf("Failed to unmarshal expected JSON message: %v", err)
			}
			var actualMsg any
			if err := json.Unmarshal(got.Msg, &actualMsg); err != nil {
				t.Fatalf("Failed to unmarshal actual JSON message: %v", err)
			}
			if !reflect.DeepEqual(expectedMsg, actualMsg) {
				t.Errorf("Msg JSON mismatch: expected %s, got %s", string(tt.msgOut.Msg), string(got.Msg))
			}
		})
	}

}
