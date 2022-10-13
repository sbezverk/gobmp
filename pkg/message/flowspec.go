package message

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/flowspec"
)

// unicast process nlri 14 afi 1/2 safi 1 messages and generates UnicastPrefix messages
func (p *producer) flowspec(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]*Flowspec, error) {
	var operation string
	switch op {
	case 0:
		operation = "add"
	case 1:
		operation = "del"
	default:
		return nil, fmt.Errorf("unknown operation %d", op)
	}

	fsnlri, err := nlri.GetFlowspecNLRI()
	if err != nil {
		return nil, err
	}
	fs := &Flowspec{
		Action:         operation,
		RouterIP:       p.speakerIP,
		PeerType:       uint8(ph.PeerType),
		PeerASN:        ph.PeerAS,
		Timestamp:      ph.GetPeerTimestamp(),
		BaseAttributes: update.BaseAttributes,
		SpecHash:       fsnlri.GetSpecHash(),
	}

	if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
		// Last element in AS_PATH would be the AS of the origin
		fs.OriginAS = int32(ases[len(ases)-1])
	}

	fs.Nexthop = nlri.GetNextHop()
	fs.Spec = fsnlri.Spec
	fs.PeerIP = ph.GetPeerAddrString()
	fs.IsIPv4 = !nlri.IsIPv6NLRI()
	fs.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
	if f, err := ph.IsAdjRIBInPost(); err == nil {
		fs.IsAdjRIBInPost = f
	}
	if f, err := ph.IsAdjRIBOutPost(); err == nil {
		fs.IsAdjRIBOutPost = f
	}
	if f, err := ph.IsLocRIBFiltered(); err == nil {
		fs.IsLocRIBFiltered = f
	}

	return []*Flowspec{fs}, nil
}

func (fs *Flowspec) UnmarshalJSON(b []byte) error {
	o := Flowspec{}
	var objmap map[string]json.RawMessage
	if err := json.Unmarshal(b, &objmap); err != nil {
		return err
	}
	// action is mandatory
	if err := json.Unmarshal(objmap["action"], &o.Action); err != nil {
		return err
	}
	// spec_has is mandatory because it serves as a key
	if err := json.Unmarshal(objmap["spec_hash"], &o.SpecHash); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["base_attrs"], &o.BaseAttributes); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["is_ipv4"], &o.IsIPv4); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["is_nexthop_ipv4"], &o.IsNexthopIPv4); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["nexthop"], &o.Nexthop); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["peer_asn"], &o.PeerASN); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["router_ip"], &o.RouterIP); err != nil {
		return err
	}
	if err := json.Unmarshal(objmap["timestamp"], &o.Timestamp); err != nil {
		return err
	}
	if s, ok := objmap["spec"]; ok {
		var specs []map[string]interface{}
		if err := json.Unmarshal(s, &specs); err != nil {
			return err
		}
		o.Spec = make([]flowspec.Spec, 0)
		for _, spec := range specs {
			switch flowspec.SpecType(spec["type"].(float64)) {
			case flowspec.Type1:
				fallthrough
			case flowspec.Type2:
				s, err := makePrefixSpec(spec)
				if err != nil {
					return err
				}
				o.Spec = append(o.Spec, s)
			case flowspec.Type3:
				s, err := makeGenericSpec(spec)
				if err != nil {
					return err
				}
				o.Spec = append(o.Spec, s)
			default:
				glog.Errorf("Unknown type: %+v", spec["type"].(flowspec.SpecType))
			}
		}
	}
	*fs = o

	return nil
}

func makePrefixSpec(spec map[string]interface{}) (flowspec.Spec, error) {
	s := &flowspec.PrefixSpec{}
	if p, ok := spec["type"]; ok {
		s.SpecType = uint8(p.(float64))
	}
	if p, ok := spec["prefix_len"]; ok {
		s.PrefixLength = uint8(p.(float64))
	}
	if p, ok := spec["prefix"]; ok {
		s.Prefix = make([]byte, len(p.(string)))
		copy(s.Prefix, []byte(p.(string)))
	}

	return s, nil
}

func makeGenericSpec(spec map[string]interface{}) (flowspec.Spec, error) {
	s := &flowspec.GenericSpec{}
	var err error
	if p, ok := spec["type"]; ok {
		s.SpecType = uint8(p.(float64))
	}
	if s.OpVal, err = makeOpValPair(spec["op_val_pairs"].([]interface{})); err != nil {
		return nil, err
	}

	return s, nil
}

func makeOpValPair(src []interface{}) ([]*flowspec.OpVal, error) {
	ovp := make([]*flowspec.OpVal, len(src))
	for i, s := range src {
		o := &flowspec.OpVal{}
		if p, ok := s.(map[string]interface{})["value"]; ok {
			o.Val = make([]byte, len(p.(string)))
			copy(o.Val, []byte(p.(string)))
		}
		if p, ok := s.(map[string]interface{})["operator"]; ok {
			op := &flowspec.Operator{}
			if e, ok := p.(map[string]interface{})["value_length"]; ok {
				op.Length = uint8(e.(float64))
			}
			if e, ok := p.(map[string]interface{})["end_of_list_bit"]; ok {
				op.EOLBit = e.(bool)
			}
			if e, ok := p.(map[string]interface{})["and_bit"]; ok {
				op.ANDBit = e.(bool)
			}
			if e, ok := p.(map[string]interface{})["less_than"]; ok {
				op.LTBit = e.(bool)
			}
			if e, ok := p.(map[string]interface{})["greater_than"]; ok {
				op.GTBit = e.(bool)
			}
			if e, ok := p.(map[string]interface{})["equal"]; ok {
				op.EQBit = e.(bool)
			}
			o.Op = op
		}
		ovp[i] = o
	}

	return ovp, nil
}
