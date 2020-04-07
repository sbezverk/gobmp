package database

import "fmt"

const LSNodeName = "LSNode"

type LSNode struct {
	Key          string `json:"_key,omitempty"`
	Name         string `json:"Name,omitempty"`
	RouterID     string `json:"RouterID,omitempty"`
	//BGPID        string `json:"BGPID,omitempty"`
	ASN          string `json:"ASN,omitempty"`
        SRGB         string `json:"SRGB,omitempty"`
        SIDIndex     string `json:"SIDIndex,omitempty"`
        PrefixSID    string `json:"PrefixSID,omitempty"`
	IGPID        string `json:"IGPID,omitempty"`
}

func (r LSNode) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *LSNode) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *LSNode) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if r.RouterID != "" {
		ret = fmt.Sprintf("%s", r.RouterID)
//		ret = fmt.Sprintf("Router/%s", r.RouterIP)
		err = nil
	}
	return ret, err
}

func (r LSNode) GetType() string {
	return LSNodeName
}

