package bgp

// BaseAttributes defines a structure holding BGP's basic, non nlri based attributes,
// codes for each can be found:
// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-2
type BaseAttributes struct {
	BaseAttrHash  string   `json:"base_attr_hash,omitempty"`
	Origin        string   `json:"origin,omitempty"`
	ASPath        []uint32 `json:"as_path,omitempty"`
	ASPathCount   int32    `json:"as_path_count,omitempty"`
	Nexthop       string   `json:"nexthop,omitempty"`
	MED           uint32   `json:"med,omitempty"`
	LocalPref     uint32   `json:"local_pref,omitempty"`
	IsAtomicAgg   bool     `json:"is_atomic_agg"`
	Aggregator    string   `json:"aggregator,omitempty"`
	CommunityList string   `json:"community_list,omitempty"`
	OriginatorID  string   `json:"originator_id,omitempty"`
	// ClusterList
	ExtCommunityList string `json:"ext_community_list,omitempty"`
	// AS4Path
	// AS4PathCount
	// AS4Aggregator
	// PMSITunnel
	// TunnelEncapAttr
	// TraficEng
	// IPv6SpecExtCommunity
	// AIGP
	// PEDistinguisherLable
	LgCommunityList string `json:"large_community_list,omitempty"`
	// SecPath
	// AttrSet
}

// UnmarshalBGPBaseAttributes discovers all present Base Attributes in BGP Update
// and instantiates BaseAttributes object
func UnmarshalBGPBaseAttributes(b []byte) (*BaseAttributes, error) {
	baseAttr := BaseAttributes{}

	for p:=0;p<len()b; {
		flag := b[p]
		p++
		t := b[p]
		p += 2
		var l uint16
		// Checking for Extened
		if f&0x10 == 0x10 {
			l = binary.BigEndian.Uint16(b[p : p+2])
			p += 2
		} else {
			l = uint16(b[p])
			p++
		}
		switch t {
		case 1:
		}
	}
	return &baseAttr, nil
}

// // getAttrOrigin returns the value of Origin attribute if it is defined, otherwise it returns nil
// func getAttrOrigin() *string {
// 	var o string
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 1 {
// 			switch attr.Attribute[0] {
// 			case 0:
// 				o = "igp"
// 			case 1:
// 				o = "egp"
// 			case 2:
// 				o = "incomplete"
// 			}
// 			return &o
// 		}
// 	}

// 	return nil
// }

// // getAttrASPath returns a sequence of AS path segments
// func getAttrASPath() []uint32 {
// 	path := make([]uint32, 0)
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType != 2 {
// 			continue
// 		}
// 		for p := 0; p < len(attr.Attribute); {
// 			// Skipping type
// 			p++
// 			// Length of path segment in 2 bytes
// 			l := attr.Attribute[p]
// 			p++
// 			as4 := false
// 			if int(l)*4 == len(attr.Attribute)-p {
// 				as4 = true
// 			}
// 			for n := 0; n < int(l); n++ {
// 				if as4 {
// 					as := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
// 					p += 4
// 					path = append(path, as)
// 				} else {
// 					as := binary.BigEndian.Uint16(attr.Attribute[p : p+2])
// 					p += 2
// 					path = append(path, uint32(as))
// 				}

// 			}
// 		}
// 	}

// 	return path
// }

// // getAttrNextHop returns the value of Next Hop attribute if it is defined, otherwise it returns nil
// func getAttrNextHop() []byte {
// 	var nh []byte
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 3 {
// 			nh = make([]byte, attr.AttributeLength)
// 			copy(nh, attr.Attribute)
// 			return nh
// 		}
// 	}

// 	return nh
// }

// // getAttrMED returns the value of MED attribute if it is defined, otherwise it returns nil
// func getAttrMED() *uint32 {
// 	var med uint32
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 4 {
// 			med = binary.BigEndian.Uint32(attr.Attribute)
// 			return &med
// 		}
// 	}

// 	return nil
// }

// // getAttrLocalPref returns the value of LOCAL_PREF attribute if it is defined, otherwise it returns nil
// func getAttrLocalPref() *uint32 {
// 	var lp uint32
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 5 {
// 			lp = binary.BigEndian.Uint32(attr.Attribute)
// 			return &lp
// 		}
// 	}

// 	return nil
// }

// // getAttrAtomicAggregate returns 1 if ATOMIC_AGGREGATE exists, 0 if does not
// func getAttrAtomicAggregate() bool {
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 6 {
// 			return true
// 		}
// 	}

// 	return false
// }

// // getAttrAggregator returns the value of AGGREGATOR attribute if it is defined, otherwise it returns nil
// func getAttrAggregator() []byte {
// 	var agg []byte
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 7 {
// 			agg = make([]byte, attr.AttributeLength)
// 			copy(agg, attr.Attribute)
// 			return agg
// 		}
// 	}

// 	return agg
// }

// // getAttrCommunity returns a slice of communities
// func getAttrCommunity() []uint32 {
// 	comm := make([]uint32, 0)
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType != 8 {
// 			continue
// 		}
// 		for p := 0; p < len(attr.Attribute); {
// 			c := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
// 			p += 4
// 			comm = append(comm, c)
// 		}
// 	}

// 	return comm
// }

// // getAttrCommunityString returns the string with comma separated communities.
// func getAttrCommunityString() string {
// 	var communities string
// 	cs := up.getAttrCommunity()
// 	for i, c := range cs {
// 		communities += fmt.Sprintf("%d:%d", (0xffff0000&c)>>16, 0xffff&c)
// 		if i < len(cs)-1 {
// 			communities += ", "
// 		}
// 	}

// 	return communities
// }

// // getAttrOriginatorID returns the value of ORIGINATOR_ID attribute if it is defined, otherwise it returns nil
// func getAttrOriginatorID() []byte {
// 	var id []byte
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 9 {
// 			id = make([]byte, attr.AttributeLength)
// 			copy(id, attr.Attribute)
// 			return id
// 		}
// 	}

// 	return id
// }

// // getAttrClusterListID returns the value of CLUSTER_LIST attribute if it is defined, otherwise it returns nil
// func getAttrClusterListID() []byte {
// 	var l []byte
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 10 {
// 			l = make([]byte, attr.AttributeLength)
// 			copy(l, attr.Attribute)
// 			return l
// 		}
// 	}

// 	return l
// }

// // getAttrExtCommunity returns a slice with all extended communities found in bgp update
// func getAttrExtCommunity() ([]ExtCommunity, error) {
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 16 {
// 			return UnmarshalBGPExtCommunity(attr.Attribute)
// 		}
// 	}

// 	return nil, fmt.Errorf("not found")
// }

// // getAttrLgCommunity returns a slice with all large communities found in bgp update
// func getAttrLgCommunity() ([]LgCommunity, error) {
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 32 {
// 			return UnmarshalBGPLgCommunity(attr.Attribute)
// 		}
// 	}

// 	return nil, fmt.Errorf("not found")
// }

// // GetExtCommunityRT returns  a slice of Route Target EXTENDED_COMMUNITY
// func GetExtCommunityRT() ([]ExtCommunity, error) {
// 	rts := make([]ExtCommunity, 0)
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 16 {
// 			all, err := UnmarshalBGPExtCommunity(attr.Attribute)
// 			if err != nil {
// 				return nil, err
// 			}
// 			for _, c := range all {
// 				if c.IsRouteTarget() {
// 					rts = append(rts, c)
// 				}
// 			}
// 			return rts, nil
// 		}
// 	}

// 	return nil, fmt.Errorf("not found")
// }

// // getAttrAS4Path returns a sequence of AS4 path segments
// func getAttrAS4Path() []uint32 {
// 	path := make([]uint32, 0)
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType != 17 {
// 			continue
// 		}
// 		for p := 0; p < len(attr.Attribute); {
// 			// Skipping type
// 			p++
// 			// Length of path segment in 4 bytes
// 			l := attr.Attribute[p]
// 			p++
// 			for n := 0; n < int(l); n++ {
// 				as := binary.BigEndian.Uint32(attr.Attribute[p : p+4])
// 				p += 4
// 				path = append(path, as)
// 			}
// 		}
// 	}

// 	return path
// }

// // getAttrAS4Aggregator returns the value of AS4 AGGREGATOR attribute if it is defined, otherwise it returns nil
// func getAttrAS4Aggregator() []byte {
// 	var agg []byte
// 	for _, attr := range up.PathAttributes {
// 		if attr.AttributeType == 18 {
// 			agg = make([]byte, attr.AttributeLength)
// 			copy(agg, attr.Attribute)
// 			return agg
// 		}
// 	}

// 	return agg
// }
