package database

import "fmt"

const L3VPNNodeName = "L3VPNNode"

type L3VPNNode struct {
        Key              string `json:"_key,omitempty"`
        RD               []string `json:"RD,omitempty"`
        RouterID         string `json:"RouterID,omitempty"`
        ControlPlaneID   string `json:"ControlPlaneID,omitempty"`
        ASN              string `json:"ASN,omitempty"`
        Prefix_SID       string `json:"Prefix_SID,omitempty"`
        ExtComm          string `json:"ExtComm,omitempty"`
}

func (r L3VPNNode) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *L3VPNNode) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *L3VPNNode) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if (r.RouterID != "") {
		ret = fmt.Sprintf("%s", r.RouterID)
		err = nil
	}
	return ret, err
}

func (r L3VPNNode) GetType() string {
	return L3VPNNodeName
}
