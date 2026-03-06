package dumper

import (
	"encoding/json"
	"log"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
)

type msgOut struct {
	MsgType int             `json:"msg_type"`
	MsgHash string          `json:"msg_hash,omitempty"`
	Msg     json.RawMessage `json:"msg_data,omitempty"`
}

type pubwriter struct {
	output *log.Logger
}

func (p *pubwriter) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m := msgOut{
		MsgType: msgType,
		MsgHash: string(msgHash),
		Msg:     json.RawMessage(msg),
	}

	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	p.output.Println(string(b))

	return nil
}

func (p *pubwriter) Stop() {
	p.output.Printf("gobmp is stopping...")
}

// NewDumper returns a new instance of standard out dumper.
func NewDumper() pub.Publisher {
	pw := pubwriter{
		output: log.New(os.Stdout, "", 0),
	}

	return &pw
}
