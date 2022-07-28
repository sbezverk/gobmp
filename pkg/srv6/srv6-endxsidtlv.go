package srv6

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

const (
	// EndXSIDTLVMinLen defines minimum valid length of End.X SID TLV
	EndXSIDTLVMinLen = 22
)

// EndXSIDFlags defines a structure of SRv6 End X SID's Flags
//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |B|S|P| Reserved|
// +-+-+-+-+-+-+-+-+
// https://tools.ietf.org/html/draft-ietf-idr-bgpls-srv6-ext-07#section-4.1
type EndXSIDFlags struct {
	BFlag bool `json:"b_flag"`
	SFlag bool `json:"s_flag"`
	PFlag bool `json:"p_flag"`
}

// UnmarshalEndXSIDFlagss builds a new End.X SID's flags object
func UnmarshalEndXSIDFlags(b []byte) (*EndXSIDFlags, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("not enough bytes to unmarshal SRv6 Locator Flags")
	}
	return &EndXSIDFlags{
		BFlag: b[0]&0x80 == 0x80,
		SFlag: b[0]&0x40 == 0x40,
		PFlag: b[0]&0x20 == 0x20,
	}, nil
}

// EndXSIDTLV defines SRv6 End.X SID TLV object
// No RFC yet
type EndXSIDTLV struct {
	Type             uint16        `json:"type,omitempty"`
	Length           uint16        `json:"length,omitempty"`
	EndpointBehavior uint16        `json:"endpoint_behavior"`
	Flags            *EndXSIDFlags `json:"flags,omitempty"`
	Algorithm        uint8         `json:"algorithm"`
	Weight           uint8         `json:"weight"`
	SID              string        `json:"sid,omitempty"`
	SubTLVs          []SubTLV      `json:"sub_tlvs,omitempty"`
}

func (e *EndXSIDTLV) GetType() uint16 {
	return e.Type
}
func (e *EndXSIDTLV) GetLen() uint16 {
	return e.Length
}

func (e *EndXSIDTLV) UnmarshalJSON(b []byte) error {
	result := &EndXSIDTLV{}
	var objVal map[string]json.RawMessage
	if err := json.Unmarshal(b, &objVal); err != nil {
		return err
	}

	// Type             uint16        `json:"type,omitempty"`
	if v, ok := objVal["type"]; ok {
		if err := json.Unmarshal(v, &result.Type); err != nil {
			return err
		}
	}
	// Length           uint16        `json:"length,omitempty"`
	if v, ok := objVal["length"]; ok {
		if err := json.Unmarshal(v, &result.Length); err != nil {
			return err
		}
	}
	// EndpointBehavior uint16        `json:"endpoint_behavior,omitempty"`
	if v, ok := objVal["endpoint_behavior"]; ok {
		if err := json.Unmarshal(v, &result.EndpointBehavior); err != nil {
			return err
		}
	}
	// Flags            *EndXSIDFlags `json:"flags,omitempty"`
	if v, ok := objVal["flags"]; ok {
		if err := json.Unmarshal(v, &result.Flags); err != nil {
			return err
		}
	}
	// Algorithm        uint8         `json:"algorithm,omitempty"`
	if v, ok := objVal["algorithm"]; ok {
		if err := json.Unmarshal(v, &result.Algorithm); err != nil {
			return err
		}
	}
	// Weight           uint8         `json:"weight,omitempty"`
	if v, ok := objVal["weigh"]; ok {
		if err := json.Unmarshal(v, &result.Weight); err != nil {
			return err
		}
	}
	// SID              string        `json:"sid,omitempty"`
	if v, ok := objVal["sid"]; ok {
		if err := json.Unmarshal(v, &result.SID); err != nil {
			return err
		}
	}
	if v, ok := objVal["sub_tlvs"]; ok {
		var stlvs []map[string]json.RawMessage
		if err := json.Unmarshal(v, &stlvs); err != nil {
			return err
		}
		var err error
		result.SubTLVs, err = UnmarshalJSONAllSubTLV(stlvs)
		if err != nil {
			return err
		}
	}

	*e = *result

	return nil
}

// UnmarshalSRv6EndXSIDTLV builds SRv6 End.X SID TLV object
func UnmarshalSRv6EndXSIDTLV(b []byte) (*EndXSIDTLV, error) {
	if glog.V(5) {
		glog.Infof("SRv6 End.X SID TLV Raw: %s", tools.MessageHex(b))
	}
	if len(b) < EndXSIDTLVMinLen {
		return nil, fmt.Errorf("invalid length of data %d, expected minimum of %d", len(b), EndXSIDTLVMinLen)
	}
	p := 0
	e := EndXSIDTLV{}
	if p+2 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	e.EndpointBehavior = binary.BigEndian.Uint16(b[p : p+2])
	if p+2 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p += 2
	f, err := UnmarshalEndXSIDFlags(b[p : p+1])
	if err != nil {
		return nil, err
	}
	e.Flags = f
	if p+1 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p++
	e.Algorithm = b[p]
	if p+1 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p++
	e.Weight = b[p]
	if p+2 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	p++
	// Skip reserved byte
	p++
	if p+16 > len(b) {
		return nil, fmt.Errorf("invalid input %s", tools.MessageHex(b))
	}
	sid := net.IP(b[p : p+16])
	if sid.To16() == nil {
		return nil, fmt.Errorf("invalid sid format")
	}
	e.SID = sid.To16().String()
	p += 16
	if len(b) > p {
		stlvs, err := UnmarshalAllSRv6SubTLV(b[p:])
		if err != nil {
			return nil, err
		}
		e.SubTLVs = stlvs
	}

	return &e, nil
}
