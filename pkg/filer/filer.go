package filer

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
)

// MsgOut defines structure of the message stored in the file.

type MsgOut struct {
	MsgType int    `json:"msg_type,omitempty"`
	MsgHash string `json:"msg_hash,omitempty"`
	Msg     string `json:"msg_data,omitempty"`
}

type pubfiler struct {
	file *os.File
}

func (p *pubfiler) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m := MsgOut{
		MsgType: msgType,
		MsgHash: string(msgHash),
		Msg:     string(msg),
	}
	b, err := json.Marshal(&m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s := bytes.ReplaceAll(b, []byte(`\\n`), []byte(`\n`))
	s = bytes.ReplaceAll(s, []byte(`\"`), []byte(`"`))
	_, err = p.file.Write(s)
	if err != nil {
		return err
	}

	return nil
}

func (p *pubfiler) Stop() {
	_ = p.file.Close()
}

// NewFiler returns a new instance of message filer
func NewFiler(file string) (pub.Publisher, error) {
	f, err := os.Create(file)
	if err != nil {
		return nil, err
	}
	pw := pubfiler{
		file: f,
	}

	return &pw, nil
}
