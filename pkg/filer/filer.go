package filer

import (
	"encoding/json"
	"os"
	"time"

	"github.com/sbezverk/gobmp/pkg/pub"
)

type msgOut struct {
	Type  int       `json:"type,omitempty"`
	Key   []byte    `json:"key,omitempty"`
	Value []byte    `json:"value,omitempty"`
	Time  time.Time `json:"timestamp,omitempty"`
}

type pubfiler struct {
	file *os.File
}

func (pf *pubfiler) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	m := msgOut{
		Type:  msgType,
		Key:   msgHash,
		Value: msg,
		Time:  time.Now(),
	}
	b, err := json.Marshal(&m)
	if err != nil {
		return err
	}
	_, err = pf.file.Write(b)
	if err != nil {
		return err
	}

	return nil
}

// NewFiler returns a new instance of message filer
func NewFiler(file string) pub.Publisher {
	f, err := os.Create(file)
	if err != nil {
		return nil
	}
	pw := pubfiler{
		file: f,
	}

	return &pw
}
