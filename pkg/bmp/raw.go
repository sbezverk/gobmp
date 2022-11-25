package bmp

import (
	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

type RawMessage struct {
	Msg []byte
}

func UnmarshalBMPRawMessage(b []byte) (*RawMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Raw Message Raw: %s", tools.MessageHex(b))
	}
	m := RawMessage{}
	m.Msg = make([]byte, len(b))
	copy(m.Msg, b)

	return &m, nil
}
