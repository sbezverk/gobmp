package base

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/tools"
)

// LocalRemoteIdentifierTLV defines Link Descriptor Local/Remote Identifiers TLV object
// RFC7752
type LocalRemoteIdentifierTLV struct {
	Local  uint32
	Remote uint32
}

func (lri *LocalRemoteIdentifierTLV) String() string {
	var s string
	s += "   Local/Remote Identifiers:" + "\n"
	s += fmt.Sprintf("      Local: %d\n", lri.Local)
	s += fmt.Sprintf("      Remote: %d\n", lri.Remote)

	return s
}

// MarshalJSON defines a method to Marshal Link Descriptor Local/Remote Identifiers TLV object into JSON format
func (lri *LocalRemoteIdentifierTLV) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"Local\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", lri.Local))...)
	jsonData = append(jsonData, []byte("\"Remote\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d", lri.Remote))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalLocalRemoteIdentifierTLV builds Link Descriptor Local/Remote Identifiers TLV object
func UnmarshalLocalRemoteIdentifierTLV(b []byte) (*LocalRemoteIdentifierTLV, error) {
	glog.V(6).Infof("LocalRemoteIdentifierTLV Raw: %s", tools.MessageHex(b))
	lri := LocalRemoteIdentifierTLV{
		Local:  binary.BigEndian.Uint32(b[:4]),
		Remote: binary.BigEndian.Uint32(b[4:]),
	}

	return &lri, nil
}
