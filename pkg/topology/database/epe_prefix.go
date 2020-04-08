package database

import "fmt"

const EPEPrefixName = "EPEPrefix"

type EPEPrefix struct {
	Key           string `json:"_key,omitempty"`
        Prefix        string `json:"Prefix,omitempty"`
        Length        string `json:"Length,omitempty"`
        PeerIP        string `json:"PeerIP,omitempty"`
        PeerASN       string `json:"PeerASN,omitempty"`
        Nexthop       string `json:"Nexthop,omitempty"`
	OriginASN     string `json:"OriginASN,omitempty"`
	ASPath        string `json:"ASPath,omitempty"`
        ASPathCount   string `json:"ASPathCount,omitempty"`
        MED           string `json:"MED,omitempty"`
        LocalPref      string `json:"LocalPref,omitempty"`
        CommunityList string `json:"CommunityList,omitempty"`
        ExtComm       string `json:"ExtComm,omitempty"`
        IsIPv4        string `json:"IsIPv4,omitempty"`
        IsNexthopIPv4 string `json:"IsNexthopIPv4,omitempty"`
        Labels        string `json:"Labels,omitempty"`
}

func (r EPEPrefix) GetKey() (string, error) {
	if r.Key == "" {
		return r.makeKey()
	}
	return r.Key, nil
}

func (r *EPEPrefix) SetKey() error {
	k, err := r.makeKey()
	if err != nil {
		return err
	}
	r.Key = k
	return nil
}

func (r *EPEPrefix) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if r.Prefix != "" {
		ret = fmt.Sprintf("%s_%s_%s", r.PeerIP, r.Prefix, r.Length)
		err = nil
	}
	return ret, err
}

func (r EPEPrefix) GetType() string {
	return EPEPrefixName
}
