package database

import "fmt"

const EPENodeName = "EPENode"

type EPENode struct {
	Key          string `json:"_key,omitempty"`
	Name         string `json:"Name,omitempty"`
	RouterID     string `json:"RouterID,omitempty"`
	PeerIP       []string `json:"PeerIP,omitempty"`
	ASN          string `json:"ASN,omitempty"`
}

func (r EPENode) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *EPENode) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *EPENode) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if r.RouterID != "" {
		ret = fmt.Sprintf("%s", r.RouterID)
		err = nil
	}
	return ret, err
}

func (r EPENode) GetType() string {
	return EPENodeName
}
