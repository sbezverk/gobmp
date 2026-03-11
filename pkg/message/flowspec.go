package message

import (
	"encoding/json"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/flowspec"
)

// flowspec processes MP_REACH/UNREACH NLRI for AFI 1/2 SAFI 133 and generates Flowspec messages.
// Per RFC 8955/8956, the NLRI field may contain multiple Flow Specifications.
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

	allNLRI, err := nlri.GetAllFlowspecNLRI()
	if err != nil {
		return nil, err
	}

	// RFC 8955/8956: empty MP_UNREACH means withdraw all flowspec routes
	if len(allNLRI) == 0 && operation == "del" {
		fs := p.buildFlowspecMessage(operation, nlri, ph, update, nil)
		return []*Flowspec{fs}, nil
	}

	msgs := make([]*Flowspec, 0, len(allNLRI))
	for _, fsnlri := range allNLRI {
		fs := p.buildFlowspecMessage(operation, nlri, ph, update, fsnlri)
		msgs = append(msgs, fs)
	}
	return msgs, nil
}

// buildFlowspecMessage constructs a single Flowspec message. Pass nil fsnlri for withdraw-all.
func (p *producer) buildFlowspecMessage(operation string, nlri bgp.MPNLRI, ph *bmp.PerPeerHeader, update *bgp.Update, fsnlri *flowspec.NLRI) *Flowspec {
	fs := &Flowspec{
		Action:         operation,
		RouterIP:       p.speakerIP,
		PeerType:       uint8(ph.PeerType),
		PeerASN:        ph.PeerAS,
		Timestamp:      ph.GetPeerTimestamp(),
		BaseAttributes: update.BaseAttributes,
	}

	if fsnlri != nil {
		fs.SpecHash = fsnlri.GetSpecHash()
		fs.Spec = fsnlri.Spec
	} else {
		// Withdraw-all: AFI-aware peer-scoped key to avoid IPv4/IPv6 collisions
		// and cross-peer collisions when splitAF is disabled.
		if nlri.IsIPv6NLRI() {
			fs.SpecHash = fmt.Sprintf("ipv6:withdraw-all:%s:%s", ph.GetPeerAddrString(), ph.GetPeerDistinguisherString())
		} else {
			fs.SpecHash = fmt.Sprintf("withdraw-all:%s:%s", ph.GetPeerAddrString(), ph.GetPeerDistinguisherString())
		}
	}

	if ases := update.BaseAttributes.ASPath; len(ases) != 0 {
		fs.OriginAS = ases[len(ases)-1]
	}

	fs.Nexthop = nlri.GetNextHop()
	fs.PeerIP = ph.GetPeerAddrString()
	fs.IsIPv4 = !nlri.IsIPv6NLRI()
	fs.IsNexthopIPv4 = !nlri.IsNextHopIPv6()
	if f, err := ph.IsAdjRIBInPost(); err == nil {
		fs.IsAdjRIBInPost = f
	}
	if f, err := ph.IsAdjRIBOutPost(); err == nil {
		fs.IsAdjRIBOutPost = f
	}
	if f, err := ph.IsAdjRIBOut(); err == nil {
		fs.IsAdjRIBOut = f
	}
	if f, err := ph.IsLocRIB(); err == nil {
		fs.IsLocRIB = f
	}
	if f, err := ph.IsLocRIBFiltered(); err == nil {
		fs.IsLocRIBFiltered = f
	}
	// RFC 9069: Set TableName for LocRIB peers
	if fs.IsLocRIB {
		fs.TableName = p.GetTableName(ph.GetPeerBGPIDString(), ph.GetPeerDistinguisherString())
	}

	return fs
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
			case flowspec.Type3,
				flowspec.Type4,
				flowspec.Type5,
				flowspec.Type6,
				flowspec.Type7,
				flowspec.Type8,
				flowspec.Type9,
				flowspec.Type10,
				flowspec.Type11,
				flowspec.Type12:
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
	if p, ok := spec["prefix_offset"]; ok {
		s.Offset = uint8(p.(float64))
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
	pairs, ok := spec["op_val_pairs"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid op_val_pairs field")
	}
	if s.OpVal, err = makeOpValPair(pairs); err != nil {
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
