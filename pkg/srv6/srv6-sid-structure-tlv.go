package srv6

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/internal"
)

// SIDStructure defines SRv6 SID Structure TLV object
// No RFC yet
type SIDStructure struct {
	LBLength  uint8
	LNLength  uint8
	FunLength uint8
	ArgLength uint8
}

func (st *SIDStructure) String(level ...int) string {
	var s string
	l := 0
	if level != nil {
		l = level[0]
	}
	s += internal.AddLevel(l)
	s += "SRv6 SID Structure TLV:" + "\n"

	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Locator Block length: %d\n", st.LBLength)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("Locator Node length: %d\n", st.LNLength)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("SID Function length: %d\n", st.FunLength)
	s += internal.AddLevel(l + 1)
	s += fmt.Sprintf("SID Argument length: %d\n", st.ArgLength)

	return s
}

// MarshalJSON defines a method to Marshal SRv6 SID Structure TLV object into JSON format
func (st *SIDStructure) MarshalJSON() ([]byte, error) {
	var jsonData []byte
	jsonData = append(jsonData, '{')
	jsonData = append(jsonData, []byte("\"locatorBlockLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", st.LBLength))...)
	jsonData = append(jsonData, []byte("\"locatorNodeLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", st.LNLength))...)
	jsonData = append(jsonData, []byte("\"sidFunctionLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d,", st.FunLength))...)
	jsonData = append(jsonData, []byte("\"sidArgumentLength\":")...)
	jsonData = append(jsonData, []byte(fmt.Sprintf("%d", st.ArgLength))...)
	jsonData = append(jsonData, '}')

	return jsonData, nil
}

// UnmarshalSRv6SIDStructureTLV builds SRv6 SID Structure TLV object
func UnmarshalSRv6SIDStructureTLV(b []byte) (*SIDStructure, error) {
	glog.V(6).Infof("SRv6 SID Structure TLV Raw: %s", internal.MessageHex(b))
	st := SIDStructure{}
	p := 0
	st.LBLength = b[p]
	p++
	st.LNLength = b[p]
	p++
	st.FunLength = b[p]
	p++
	st.ArgLength = b[p]

	return &st, nil
}
