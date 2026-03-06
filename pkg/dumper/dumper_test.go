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
		name   string
		msgOut msgOut
	}{
		{
			name: "test1",
			msgOut: msgOut{
				MsgType: 0,
				MsgHash: "hash1",
				Msg:     []byte(`{"field1":"value1","field2":2}`),
			},
		},
		{
			name: "test2",
			msgOut: msgOut{
				MsgType: 1,
				MsgHash: "hash2",
				Msg:     []byte(`{"field1":"value1","field2":2}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nb []byte
			buff := bytes.NewBuffer(nb)
			pw := pubwriter{
				output: log.New(buff, "", 0),
			}
			err := pw.PublishMessage(tt.msgOut.MsgType, []byte(tt.msgOut.MsgHash), tt.msgOut.Msg)
			if err != nil {
				t.Errorf("PublishMessage returned an error: %v", err)
			}
			var msgOut msgOut
			err = json.Unmarshal(buff.Bytes(), &msgOut)
			if err != nil {
				t.Errorf("Failed to unmarshal msgOut: %v", err)
			}
			if !reflect.DeepEqual(&tt.msgOut, &msgOut) {
				t.Errorf("Expected msgOut: %+v, got: %+v", tt.msgOut, msgOut)
			}
		})
	}

}
