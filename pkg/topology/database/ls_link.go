package database

import (
	"fmt"
)

const LSLinkName = "LSLink"

type LSLink struct {
	LocalRouterKey   string `json:"_from,omitempty"`
        RemoteRouterKey  string `json:"_to,omitempty"`
        Key	           string `json:"_key,omitempty"`
	LocalRouterID      string `json:"LocalRouterID,omitempty"`
	RemoteRouterID     string `json:"RemoteRouterID,omitempty"`
	Protocol           string `json:"Protocol,omitempty"`
        IGPID              string `json:"IGPID,omitempty"`
	Level              string `json:"Level,omitempty"`
	RouterID           string `json:"RouterID,omitempty"`
        NodeName           string `json:"NodeName,omitempty"`
	ASN                string `json:"ASN,omitempty"`
	LocalInterfaceIP   string `json:"FromInterfaceIP,omitempty"`
        RemoteInterfaceIP  string `json:"ToInterfaceIP,omitempty"`
	IGPMetric       string `json:"IGPMetric,omitempty"`
        TEMetric        string `json:"TEMetric,omitempty"`
        AdminGroup      string `json:"AdminGroup,omitempty"`
	MaxLinkBW       string `json:"MaxLinkBW,omitempty"`
        MaxResvBW       string `json:"MaxResvBW,omitempty"`
        UnResvBW        string `json:"UnResvBW,omitempty"`
        LinkProtection  string `json:"LinkProtection,omitempty"`
        LinkName        string `json:"LinkName,omitempty"`
	SRLG            string `json:"SRLG"`
	UniDirMinDelay  string `json:"UniDirMinDelay,omitempty"`
	AdjacencySID    string `json:"AdjacencySID,omitempty"`
}

func (l LSLink) GetKey() (string, error) {
	if l.Key == "" {
		return l.makeKey()
	}
	return l.Key, nil
}

func (l *LSLink) SetKey() error {
	k, err := l.makeKey()
	if err != nil {
		return err
	}
	l.Key = k
	return nil
}

func (l *LSLink) makeKey() (string, error) {
	err := ErrKeyInvalid
	ret := ""
	if l.LocalInterfaceIP != "" && l.RemoteInterfaceIP != "" {
		ret = fmt.Sprintf("%s_%s_%s_%s", l.LocalRouterID, l.LocalInterfaceIP, l.RemoteInterfaceIP, l.RemoteRouterID)
		err = nil
	}
	return ret, err
}

func (l LSLink) GetType() string {
	return LSLinkName
}

func (l *LSLink) SetEdge(to DBObject, from DBObject) error {
	var err error
	l.RemoteRouterID, err = GetID(to)
	if err != nil {
		return err
	}
	l.LocalRouterID, err = GetID(from)
	if err != nil {
		return err
	}
	return nil
}

