package database

import "fmt"

const EPELinkName = "EPELink"

type EPELink struct {
	Key              string `json:"_key,omitempty"`
        RouterID         string `json:"RouterID,omitempty"`
        ASN              string `json:"ASN,omitempty"`
        PeerRouterID     string `json:"PeerRouterID,omitempty"`
	LocalInterfaceIP string `json:"LocalInterfaceIP,omitempty"`
	PeerIP           string `json:"PeerIP,omitempty"`
        Protocol         string `json:"Protocol,omitempty"`
        LocalPref        string `json:"LocalPref,omitempty"`
        MED              string `json:"MED,omitempty"`
        Nexthop          string `json:"Nexthop,omitempty"`
        EPELabel         string `json:"EPELabel,omitempty"`
}

func (r EPELink) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *EPELink) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *EPELink) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if r.RouterID != "" {
		ret = fmt.Sprintf("%s_%s", r.RouterID, r.PeerIP)
		err = nil
	}
	return ret, err
}

func (r EPELink) GetType() string {
	return EPELinkName
}
