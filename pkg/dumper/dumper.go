package dumper

import (
	"log"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
)

type msgOut struct {
	MsgType int    `json:"msg_type,omitempty"`
	MsgHash string `json:"msg_hash,omitempty"`
	Msg     string `json:"msg_data,omitempty"`
}

type pubwriter struct {
	output *log.Logger
}

func (pw *pubwriter) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m := msgOut{
		MsgType: msgType,
		MsgHash: string(msgHash),
		Msg:     string(msg),
	}

	pw.output.Printf("%+v", m)

	return nil
}

// NewDumper returns a new instance of standard out  dumper
func NewDumper() pub.Publisher {
	pw := pubwriter{
		output: log.New(os.Stdout, "gobmp: ", log.Lmicroseconds),
	}

	return &pw
}
