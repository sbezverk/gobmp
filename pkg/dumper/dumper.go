package dumper

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/golang/glog"
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
	if !json.Valid(msg) {
		return fmt.Errorf("failed to publish message of type %d, hash: %s, invalid JSON detected in message data", msgType, string(msgHash))
	}
	m := msgOut{
		MsgType: msgType,
		MsgHash: string(msgHash),
		Msg:     json.RawMessage(msg),
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal message for publishing: type %d, hash %s: %w", msgType, string(msgHash), err)
	}
	p.output.Println(string(b))

	return nil
}

func (p *pubwriter) Stop() {
	glog.Info("gobmp's Dump Publisher is stopping...")
}

// NewDumper returns a new instance of standard out dumper.
func NewDumper() pub.Publisher {
	pw := pubwriter{
		output: log.New(os.Stdout, "", 0),
	}

	return &pw
}
