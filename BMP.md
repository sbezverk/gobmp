# BGP Monitoring Protocol (BMP)

https://tools.ietf.org/html/rfc7854

### BMP message types and GoBMP:
GoBMP will not need to collect and parse the following BMP message types:
```
collector
router
bmp_stat
base attribute
```

GoBMP will collect and parse the following BMP message types (details below):
```
peer
unicast_prefix 
ls_node
ls_link
ls_prefix
l3vpn
evpn
```
With much gratitude we are using OpenBMP's message parsing as a template:

https://www.snas.io/docs/

### BMP peer message:
```
// Peer Down

1: (action): down
2: (sequence): 84
3: (hash): d67b274c33ea1ff0ffe9dd781938b0de
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (name): 
6: (remote_bgp_id): 10.0.0.7
7: (router_ip): 10.1.34.1
8: (timestamp): 2020-03-18 14:36:54.114438
9: (remote_asn): 100000
10: (remote_ip): 10.0.0.7
11: (peer_rd): 0:0
12: (remote_port): 
13: (local_asn): 
14: (local_ip): 
15: (local_port): 
16: (local_bgp_id): 
17: (info_data): 
18: (adv_cap): 
19: (recv_cap): 
20: (remote_holddown): 
21: (adv_holddown): 
22: (bmp_reason): 1
23: (bgp_error_code): 6
24: (bgp_error_sub_code): 4
25: (error_text): Administratively reset
26: (is_l): 0
27: (isprepolicy): 1
28: (is_ipv4): 1
29: (is_locrib): 0
30: (is_locrib_filtered): 0
31: (table_name): 

// Peer Up

1: (action): up
2: (sequence): 93
3: (hash): d67b274c33ea1ff0ffe9dd781938b0de
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (name): 
6: (remote_bgp_id): 10.0.0.7
7: (router_ip): 10.1.34.1
8: (timestamp): 2020-03-18 14:37:13.836872
9: (remote_asn): 100000
10: (remote_ip): 10.0.0.7
11: (peer_rd): 0:0
12: (remote_port): 45085
13: (local_asn): 100000
14: (local_ip): 10.0.0.10
15: (local_port): 179
16: (local_bgp_id): 10.0.0.10
17: (info_data): 
18: (adv_cap): MPBGP (1) : afi=1 safi=1 : Unicast IPv4, MPBGP (1) : afi=1 safi=4 : Labeled Unicast IPv4, MPBGP (1) : afi=1 safi=128 : MPLS-Labeled VPN IPv4, MPBGP (1) : afi=2 safi=1 : Unicast IPv6, MPBGP (1) : afi=2 safi=128 : MPLS-Labeled VPN IPv6, MPBGP (1) : afi=16388 safi=71 : BGP-LS BGP-LS, MPBGP (1) : afi=1 safi=73 :  IPv4, Route Refresh Old (128), Route Refresh (2), 4 Octet ASN (65), ADD Path (69) : afi=1 safi=1 send/receive=3 : Unicast IPv4 Send/Receive, ADD Path (69) : afi=1 safi=4 send/receive=3 : Labeled Unicast IPv4 Send/Receive, ADD Path (69) : afi=2 safi=1 send/receive=3 : Unicast IPv6 Send/Receive, 5
19: (recv_cap): MPBGP (1) : afi=1 safi=1 : Unicast IPv4, MPBGP (1) : afi=1 safi=4 : Labeled Unicast IPv4, MPBGP (1) : afi=1 safi=128 : MPLS-Labeled VPN IPv4, MPBGP (1) : afi=2 safi=1 : Unicast IPv6, MPBGP (1) : afi=2 safi=128 : MPLS-Labeled VPN IPv6, MPBGP (1) : afi=16388 safi=71 : BGP-LS BGP-LS, MPBGP (1) : afi=1 safi=73 :  IPv4, Route Refresh Old (128), Route Refresh (2), 4 Octet ASN (65), ADD Path (69) : afi=1 safi=1 send/receive=3 : Unicast IPv4 Send/Receive, ADD Path (69) : afi=1 safi=4 send/receive=3 : Labeled Unicast IPv4 Send/Receive, ADD Path (69) : afi=2 safi=1 send/receive=3 : Unicast IPv6 Send/Receive, 5
20: (remote_holddown): 180
21: (adv_holddown): 180
22: (bmp_reason): 
23: (bgp_error_code): 
24: (bgp_error_sub_code): 
25: (error_text): 
26: (is_l): 0
27: (isprepolicy): 1
28: (is_ipv4): 1
29: (is_locrib): 0
30: (is_locrib_filtered): 0
31: (table_name): 

// Peer initialization - any peer message that comes in with action: first is not needed and should be dropped

1: (action): first

```

#### BMP unicast_prefix message:
```
// delete unicast_prefix

1: (action): del
2: (sequence): 44
3: (hash): 5214a8eb996f030b3d96784c1890ab3d
4: (router_hash): 963b507b39731b0675d3422e6f6be44c
5: (router_ip): 10.1.62.1
6: (base_attr_hash): 
7: (peer_hash): a4935a0f520cd5f72ed483d2b37f58ae
8: (peer_ip): 2.2.71.1
9: (peer_asn): 7100
10: (timestamp): 2020-03-25 22:00:53.891932
11: (prefix): 71.71.8.0
12: (prefix_len): 22
13: (is_ipv4): 1
14: (origin): 
15: (as_path): 
16: (as_path_count): 
17: (origin_as): 
18: (nexthop): 
19: (med): 
20: (local_pref): 
21: (aggregator): 
22: (community_list): 
23: (ext_community_list): 
24: (cluster_list): 
25: (isatomicagg): 
26: (is_nexthop_ipv4): 
27: (originator_id): 
28: (path_id): 0
29: (labels): 
30: (isprepolicy): 1
31: (is_adj_rib_in): 1

// add unicast_prefix

1: (action): add
2: (sequence): 46
3: (hash): 5214a8eb996f030b3d96784c1890ab3d
4: (router_hash): 963b507b39731b0675d3422e6f6be44c
5: (router_ip): 10.1.62.1
6: (base_attr_hash): 3479c4959c47a2cf634a72ce2c416fb9
7: (peer_hash): a4935a0f520cd5f72ed483d2b37f58ae
8: (peer_ip): 2.2.71.1
9: (peer_asn): 7100
10: (timestamp): 2020-03-25 22:01:33.167989
11: (prefix): 71.71.8.0
12: (prefix_len): 22
13: (is_ipv4): 1
14: (origin): igp
15: (as_path): 7100
16: (as_path_count): 1
17: (origin_as): 7100
18: (nexthop): 2.2.71.1
19: (med): 0
20: (local_pref): 0
21: (aggregator): 
22: (community_list): 
23: (ext_community_list): 
24: (cluster_list): 
25: (isatomicagg): 0
26: (is_nexthop_ipv4): 1
27: (originator_id): 
28: (path_id): 0
29: (labels): 
30: (isprepolicy): 1
31: (is_adj_rib_in): 1
```

#### BMP ls_node message:
```
// add ls_node

1: (action): add
2: (sequence): 21
3: (hash): 6ed5aeb7f5ca0bbea84bdbadb61996e9
4: (base_attr_hash): f7e177580a2209c7af48c6a90f707cc9
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 1787a325b86857cdcb82e46d2e919780
8: (peer_ip): 10.0.0.1
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:20:18.804927
11: (igp_router_id): 0000.0000.0000.0000
12: (router_id): 10.0.0.0
13: (routing_id): 0
14: (ls_id): 0
15: (mt_id): 0, 2
16: (ospf_area_id): 
17: (isis_area_id): 49.0901
18: (protocol): IS-IS_L2
19: (flags): 
20: (as_path): 
21: (local_pref): 100
22: (med): 0
23: (nexthop): 10.0.0.1
24: (name): R00
25: (isprepolicy): 1
26: (is_adj_rib_in): 1
27: (ls_sr_capabilities): I 64000 100000

Additional segment routing and SRv6 items not accounted for by OpenBMP:

BGP-LS TLV Type: 1035 (SR Algorithm) - int (i think)
BGP-LS TLV Type: 1036 (SR Local Block) - might arrive as a pair of integers
BGP-LS TLV Type: 1038 (SRv6 Capabilities TLV) - string
BGP-LS TLV Type: 266 (Node MSD) 

// delete ls_node

1: (action): del
2: (sequence): 23
3: (hash): 9b20947913e9b23f4d5ccf4174e9eba4
4: (base_attr_hash): 17fcffffffffffff0000000000000000
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 6c6ba2119bddb79001663deb1801dfcc
8: (peer_ip): 10.0.0.2
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:25:05.143072
11: (igp_router_id): 0000.0000.0001.0000
12: (router_id): 0.0.0.0
13: (routing_id): 0
14: (ls_id): 0
15: (mt_id): 
16: (ospf_area_id): 
17: (isis_area_id): 
18: (protocol): IS-IS_L2
19: (flags): 
20: (as_path): 
21: (local_pref): 0
22: (med): 0
23: (nexthop): 
24: (name): 
25: (isprepolicy): 1
26: (is_adj_rib_in): 1
27: (ls_sr_capabilities): 

```
#### BMP ls_link message:
```
// add ls_link

1: (action): add
2: (sequence): 193
3: (hash): 35c2476bc696eda06bda5837da79b16d
4: (base_attr_hash): f7e177580a2209c7af48c6a90f707cc9
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 1787a325b86857cdcb82e46d2e919780
8: (peer_ip): 10.0.0.1
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:30:09.747268
11: (igp_router_id): 0000.0000.0002.0000
12: (router_id): 10.0.0.2
13: (routing_id): 0
14: (ls_id): 0
15: (ospf_area_id): 
16: (isis_area_id): 
17: (protocol): IS-IS_L2
18: (as_path): 
19: (local_pref): 100
20: (med): 0
21: (nexthop): 10.0.0.1
22: (mt_id): 0
23: (local_link_id): 0
24: (remote_link_id): 0
25: (intf_ip): 10.1.1.3
26: (nei_ip): 10.1.1.2
27: (igp_metric): 1
28: (admin_group): 0
29: (max_link_bw): 1000000
30: (max_resv_bw): 0
31: (unresv_bw): 0, 0, 0, 0, 0, 0, 0, 0
32: (te_default_metric): 1
33: (link_protection): 
34: (mpls_proto_mask): 
35: (srlg): 
36: (link_name): 
37: (remote_node_hash): 6ed5aeb7f5ca0bbea84bdbadb61996e9
38: (local_node_hash): c2679dc1c0d5615c23b3ec45f59f6b15
39: (remote_igp_router_id): 0000.0000.0000.0000
40: (remote_router_id): 10.0.0.0
41: (local_node_asn): 100000
42: (remote_node_asn): 100000
43: (peer_node_sid): 
44: (isprepolicy): 1
45: (is_adj_rib_in): 1
46: (ls_adjacency_sid): BVL 0 24004, VL 0 24005

Additional segment routing and SRv6 items not accounted for by OpenBMP:

BGP-LS TLV Type: 267 (Link MSD)

// delete ls_link

1: (action): del
2: (sequence): 102
3: (hash): 9f60356cda03f1850cdbc818c9440a60
4: (base_attr_hash): 17fcffffffffffff0000000000000000
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 6c6ba2119bddb79001663deb1801dfcc
8: (peer_ip): 10.0.0.2
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:25:00.023351
11: (igp_router_id): 0000.0000.0000.0000
12: (router_id): ::
13: (routing_id): 0
14: (ls_id): 0
15: (ospf_area_id): 
16: (isis_area_id): 
17: (protocol): IS-IS_L2
18: (as_path): 
19: (local_pref): 0
20: (med): 0
21: (nexthop): 
22: (mt_id): 2
23: (local_link_id): 0
24: (remote_link_id): 0
25: (intf_ip): 10:1:1::
26: (nei_ip): 10:1:1::1
27: (igp_metric): 0
28: (admin_group): 0
29: (max_link_bw): 0
30: (max_resv_bw): 0
31: (unresv_bw): 
32: (te_default_metric): 0
33: (link_protection): 
34: (mpls_proto_mask): 
35: (srlg): 
36: (link_name): 
37: (remote_node_hash): 9b20947913e9b23f4d5ccf4174e9eba4
38: (local_node_hash): 6ed5aeb7f5ca0bbea84bdbadb61996e9
39: (remote_igp_router_id): 0000.0000.0001.0000
40: (remote_router_id): ::
41: (local_node_asn): 100000
42: (remote_node_asn): 100000
43: (peer_node_sid): 
44: (isprepolicy): 1
45: (is_adj_rib_in): 1
46: (ls_adjacency_sid): 

```
#### BMP ls_prefix message:

```
// add ls_prefix

1: (action): add
2: (sequence): 201
3: (hash): 47d904fe7803fa73c61ff126dd8c27d2
4: (base_attr_hash): f7e177580a2209c7af48c6a90f707cc9
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 1787a325b86857cdcb82e46d2e919780
8: (peer_ip): 10.0.0.1
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:30:09.739779
11: (igp_router_id): 0000.0000.0002.0000
12: (router_id): 0.0.0.0
13: (routing_id): 0
14: (ls_id): 0
15: (ospf_area_id): 
16: (isis_area_id): 
17: (protocol): IS-IS_L2
18: (as_path): 
19: (local_pref): 100
20: (med): 0
21: (nexthop): 10.0.0.1
22: (local_node_hash): c2679dc1c0d5615c23b3ec45f59f6b15
23: (mt_id): 0
24: (ospf_route_type): 
25: (igp_flags): 
26: (route_tag): 0
27: (ext_route_tag): 0
28: (ospf_fwd_addr): 0.0.0.0
29: (igp_metric): 0
30: (prefix): 10.0.0.2
31: (prefix_len): 32
32: (isprepolicy): 1
33: (is_adj_rib_in): 1
34: (ls_prefix_sid): N SPF 2

// delete ls_prefix

1: (action): del
2: (sequence): 136
3: (hash): 8b3daeb20e905895d8cfab34220b5689
4: (base_attr_hash): 17fcffffffffffff0000000000000000
5: (router_hash): 963b507b39731b0675d3422e6f6be44c
6: (router_ip): 10.1.62.1
7: (peer_hash): 30b1ce11e0c436dc3e37dc7342b12be8
8: (peer_ip): 10.0.0.0
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:25:05.134138
11: (igp_router_id): 0000.0000.0001.0000
12: (router_id): 0.0.0.0
13: (routing_id): 0
14: (ls_id): 0
15: (ospf_area_id): 
16: (isis_area_id): 
17: (protocol): IS-IS_L2
18: (as_path): 
19: (local_pref): 0
20: (med): 0
21: (nexthop): 
22: (local_node_hash): 9b20947913e9b23f4d5ccf4174e9eba4
23: (mt_id): 0
24: (ospf_route_type): 
25: (igp_flags): 
26: (route_tag): 0
27: (ext_route_tag): 0
28: (ospf_fwd_addr): 0.0.0.0
29: (igp_metric): 0
30: (prefix): 10.0.0.1
31: (prefix_len): 32
32: (isprepolicy): 1
33: (is_adj_rib_in): 1
34: (ls_prefix_sid): 

```
#### BMP ls_srv6_sid message:
```
// this one is new, so we'll go with the initial gobmp parsing (with comments inline):

Withdrawn Routes Length: 0
Total Path Attribute Length: 184
Attribute Type: 14 (MP_REACH_NLRI)
Address Family ID: 16388
Subsequent Address Family ID: 71
Next Hop Network Address: 192.168.8.8
NLRI Type: SRv6 SID NLRI                                      // is this a new message type, or did it come as an ls_prefix message?
Total NLRI Length: 65
Protocol ID: IS-IS Level 2                                    // aligns with field 17 in openbmp ls_prefix
Identifier: 0
Node Descriptor TLVs:
   Node Descriptor Type: 256 (Local Node Descriptors)
      Node Descriptor Sub TLV Type: 512 (Autonomous System)  
         Autonomous System: 5070                              // aligns with field 9 in openbmp ls_prefix
      Node Descriptor Sub TLV Type: 513 (BGP-LS Identifier)
         BGP-LS Identifier: [ 00 00 00 00  ]                  // aligns with field 14 in openbmp ls_prefix
      Node Descriptor Sub TLV Type: 515 (IGP Router-ID)
         IGP Router-ID: [ 00 00 00 00 00 09  ]                // aligns with field 11 in openbmp ls_prefix
SRv6 SID Descriptor Object:
   SRv6 SID Information TLV Type: 518
      SID: [ 01 92 01 68 00 09 00 00 00 11 00 00 00 00 00 00  ] // new construct, roughly aligns with field 30 and 34 in ls_prefix
   Multi-Topology Identifiers:
      Identifier: 263                                           // i think this aligns with field 23 in openbmp ls_prefix
Attribute Type: 1 (ORIGIN)
   Origin: [0]
Attribute Type: 2 (AS_PATH)                                     // all the regular BGP attributes
   AS PATH: [  ]
Attribute Type: 5 (LOCAL_PREF)
   Local Pref: 100
Attribute Type: 29 (BGP-LS)
BGP-LS TLVs:
   BGP-LS TLV Type: 1250 (SRv6 Endpoint Function)               // totally new SRv6 "network programming" constructs (this gets awesome)
      Endpoint Behavior: [ 00 28  ]                            // see also: 
                                                              // https://tools.ietf.org/html/draft-ietf-spring-srv6-network-programming-13#section-9.2.1
      Flag: 00
      Algorithm: 0
   BGP-LS TLV Type: 1252 (SRv6 SID Structure)                 // also totally new SRv6 constructs
      LB Length: 40
      LN Length: 24
      Function Length: 16
      Argument Length: 0

#### BMP l3vpn message:
```
1: (action): add/del
5: (router_ip): 
8: (peer_ip): 
9: (peer_asn): 
10: (timestamp): 
11: (prefix): 
12: (prefix_len): 
13: (is_ipv4): 
14: (origin):
15: (as_path): 
16: (as_path_count): 
17: (origin_as): 
18: (nexthop): 
19: (med): 
20: (local_pref): 
21: (aggregator): 
22: (community_list): 
23: (ext_community_list)
24: (cluster_list): 
25: (isatomicagg): 
26: (is_nexthop_ipv4): 
27: (originator_id): 
28: (path_id): 
29: (labels): 
30: (isprepolicy): 
31: (is_adj_rib_in): 
32: (vpn_rd): 
33: (vpn_rd_type): 
```

#### BMP evpn message:
```
1: (action): add/del
5: (router_ip): 
8: (peer_ip): 
9: (peer_asn): 
10: (timestamp): 
11: (origin):
12: (as_path): 
13: (as_path_count): 
14: (origin_as): 
15: (nexthop): 
16: (med): 
17: (local_pref): 
18: (aggregator): 
19: (community_list): 
20: (ext_community_list)
21: (cluster_list): 
22: (isatomicagg): 
23: (is_nexthop_ipv4): 
24: (originator_id): 
25: (path_id): 
26: (isprepolicy): 
27: (is_adj_rib_in): 
28: (rd): 
29: (rd_type): 
30: (rd_type): 
31: (orig_router_ip_len): 
32: (eth_tag): 
33: (eth_segment_id): 
34: (mac_len): 
35: (mac): 
36: (ip_len): 
37: (ip): 
38: (label): 
39: (label): 
```
```
