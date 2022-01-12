package filer

import (
	"encoding/json"
	"os"

	"github.com/sbezverk/gobmp/pkg/pub"
)

// MsgOut defines structure of the message stored in the file.
type MsgOut struct {
	Type  int    `json:"type,omitempty"`
	Key   []byte `json:"key,omitempty"`
	Value []byte `json:"value,omitempty"`
}

type pubfiler struct {
	file *os.File
}

func (p *pubfiler) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m := MsgOut{
		Type:  msgType,
		Key:   msgHash,
		Value: msg,
	}
	b, err := json.Marshal(&m)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = p.file.Write(b)
	if err != nil {
		return err
	}

	return nil
}

func (p *pubfiler) Stop() {
	p.file.Close()
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
