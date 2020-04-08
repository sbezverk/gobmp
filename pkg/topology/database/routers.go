package database

import "fmt"

const RouterName = "Routers"

type Router struct {
	Key          string `json:"_key,omitempty"`
	Name         string `json:"Name,omitempty"`
	RouterIP     string `json:"RouterIP,omitempty"`
	BGPID        string `json:"BGPID,omitempty"`
	ASN          string `json:"ASN,omitempty"`
        SRGB         string `json:"SRGB,omitempty"`
        NodeSIDIndex string `json:"NodeSIDIndex,omitempty"`
        SRNodeSID    string `json:"SRNodeSID,omitempty"`
        PeeringType  string `json:"PeerType,omitempty"`
}

func (r Router) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *Router) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *Router) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if r.RouterIP != "" {
		ret = fmt.Sprintf("%s", r.RouterIP)
//		ret = fmt.Sprintf("Router/%s", r.RouterIP)
		err = nil
	}
	return ret, err
}

func (r Router) GetType() string {
	return RouterName
}
