package dumper

import (
	"encoding/json"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
)

type msgOut struct {
	MsgType int    `json:"msg_type,omitempty"`
	MsgHash []byte `json:"msg_hash,omitempty"`
	Msg     []byte `json:"msg_data,omitempty"`
}

type pubwriter struct {
	output *os.File
}

func (pw *pubwriter) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	var err error
	m := msgOut{
		MsgType: msgType,
		MsgHash: msgHash,
		Msg:     msg,
	}
	b, err := json.Marshal(&m)
	if err != nil {
		return err
	}
	_, err = pw.write(b)

	return err
}

func (pw *pubwriter) write(msg []byte) (int, error) {
	return pw.output.Write(msg)
}

// NewDumper returns a new instance of standard out  dumper
func NewDumper() pub.Publisher {
	pw := pubwriter{
		output: os.Stdout,
	}

	return &pw
}
