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
ls_srv6_sid
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
27: (is_prepolicy): 1
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
27: (is_prepolicy): 1
28: (is_ipv4): 1
29: (is_locrib): 0
30: (is_locrib_filtered): 0
31: (table_name):

// Peer initialization - any peer message that comes in with action "first" is not needed and should be dropped

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
30: (is_prepolicy): 1
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
30: (is_prepolicy): 1
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
16: (area_id):
17: (protocol): IS-IS_L2
18: (flags):
19: (as_path):
20: (local_pref): 100
21: (med): 0
22: (nexthop): 10.0.0.1
23: (name): R00
24: (is_prepolicy): 1
25: (is_adj_rib_in): 1
26: (ls_sr_capabilities): I 64000 100000

Additional segment routing and SRv6 items not accounted for by OpenBMP:

BGP-LS TLV Type: 1035 (SR Algorithm) - int (i think)
BGP-LS TLV Type: 1036 (SR Local Block) - might arrive as a pair of integers
BGP-LS TLV Type: 1038 (SRv6 Capabilities TLV) - string
BGP-LS TLV Type: 266 (Node MSD)

Future:
     +----------+------------------------------+
     | MSD Type |    Description               |
     +----------+------------------------------+
     |   TBD    | Maximum Segments Left        |
     |   TBD    | Maximum End Pop              |
     |   TBD    | Maximum T.Insert             |
     |   TBD    | Maximum T.Encaps             |
     |   TBD    | Maximum End D                |
     +----------+------------------------------+

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
16: (area_id):
17: (protocol): IS-IS_L2
18: (flags):
19: (as_path):
20: (local_pref): 0
21: (med): 0
22: (nexthop):
23: (name):
24: (is_prepolicy): 1
25: (is_adj_rib_in): 1
26: (ls_sr_capabilities):

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
15: (area_id): 0
16: (protocol): IS-IS_L2
17: (as_path):
18: (local_pref): 100
19: (med): 0
20: (nexthop): 10.0.0.1
21: (mt_id): 0
22: (local_link_id): 0
23: (remote_link_id): 0
24: (intf_ip): 10.1.1.3
25: (nei_ip): 10.1.1.2
26: (igp_metric): 1
27: (admin_group): 0
28: (max_link_bw): 0
29: (max_resv_bw): 0
30: (unresv_bw):
31: (max_link_bw_kbps): 1000000
32: (max_resv_bw_kbps): 0
33: (unresv_bw_kbps): 0, 0, 0, 0, 0, 0, 0, 0
34: (te_default_metric): 1
35: (link_protection):
36: (mpls_proto_mask):
37: (srlg):
38: (link_name):
39: (remote_node_hash): 6ed5aeb7f5ca0bbea84bdbadb61996e9
40: (local_node_hash): c2679dc1c0d5615c23b3ec45f59f6b15
41: (remote_igp_router_id): 0000.0000.0000.0000
42: (remote_router_id): 10.0.0.0
43: (local_node_asn): 100000
44: (remote_node_asn): 100000
45: (peer_node_sid):
46: (is_prepolicy): 1
47: (is_adj_rib_in): 1
48: (ls_adjacency_sid): BVL 0 24004, VL 0 24005

Additional segment routing not accounted for by OpenBMP:

BGP-LS TLV Type: 267 (Link MSD)
per https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-16#section-2.3.2:
BGP-LS TLV:
   |     1114    | Unidirectional link delay
   |     1115    | Min/Max Unidirectional link delay
   |     1116    | Unidirectional Delay Variation
   |     1117    | Unidirectional packet loss
   |     1118    | Unidirectional residual bandwidth
   |     1119    | Unidirectional available bandwidth
   |     1120    | Unidirectional bandwidth utilization

SRv6 items

   BGP-LS TLV Type: 1106 (SRv6 End.X SID TLV)
      SRv6 End.X SID TLV:
         Endpoint Behavior: 6
         Flag: 00
         Algorithm: 0
         Weight: 0
         SID: [ 01 92 01 68 00 08 00 00 00 40 00 00 00 00 00 00  ]

Bonus item (OpenBMP never carried remote node router ID field, which would be very nice to add):

   BGP-LS TLV Type: 1030 (IPv4 Router-ID of Remote Node)
      IPv4 Router-ID of Remote Node: 192.168.9.9


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
15: (area_id):
16: (protocol): IS-IS_L2
17: (as_path):
18: (local_pref): 0
19: (med): 0
20: (nexthop):
21: (mt_id): 2
22: (local_link_id): 0
23: (remote_link_id): 0
24: (intf_ip): 10:1:1::
25: (nei_ip): 10:1:1::1
26: (igp_metric): 0
27: (admin_group): 0
28: (max_link_bw): 0
29: (max_resv_bw): 0
30: (unresv_bw):
31: (max_link_bw_kbps): 0
32: (max_resv_bw_kbps): 0
33: (unresv_bw_kbps):
34: (te_default_metric): 0
35: (link_protection):
36: (mpls_proto_mask):
37: (srlg):
38: (link_name):
39: (remote_node_hash): 9b20947913e9b23f4d5ccf4174e9eba4
40: (local_node_hash): 6ed5aeb7f5ca0bbea84bdbadb61996e9
41: (remote_igp_router_id): 0000.0000.0001.0000
42: (remote_router_id): ::
43: (local_node_asn): 100000
44: (remote_node_asn): 100000
45: (peer_node_sid):
46: (is_prepolicy): 1
47: (is_adj_rib_in): 1
48: (ls_adjacency_sid):

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
15: (area_id):
16: (protocol): IS-IS_L2
17: (as_path):
18: (local_pref): 100
19: (med): 0
20: (nexthop): 10.0.0.1
21: (local_node_hash): c2679dc1c0d5615c23b3ec45f59f6b15
22: (mt_id): 0
23: (ospf_route_type):
24: (igp_flags):
25: (route_tag): 0
26: (ext_route_tag): 0
27: (ospf_fwd_addr): 0.0.0.0
28: (igp_metric): 0
29: (prefix): 10.0.0.2
30: (prefix_len): 32
31: (is_prepolicy): 1
32: (is_adj_rib_in): 1
33: (ls_prefix_sid): N SPF 2

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
15: (area_id):
16: (protocol): IS-IS_L2
17: (as_path):
18: (local_pref): 0
29: (med): 0
20: (nexthop):
21: (local_node_hash): 9b20947913e9b23f4d5ccf4174e9eba4
22: (mt_id): 0
23: (ospf_route_type):
24: (igp_flags):
25: (route_tag): 0
26: (ext_route_tag): 0
27: (ospf_fwd_addr): 0.0.0.0
28: (igp_metric): 0
39: (prefix): 10.0.0.1
30: (prefix_len): 32
31: (is_prepolicy): 1
32: (is_adj_rib_in): 1
33: (ls_prefix_sid):

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
```
#### BMP l3vpn message:
```
// add l3vpn (prefix) message

1: (action): add
2: (sequence): 35
3: (hash): 332047c6ca64451ed6f5ddb92710a29a
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (router_ip): 10.1.34.1
6: (base_attr_hash): 22155edb81a03c848f36193dfd3e48f3
7: (peer_hash): d67b274c33ea1ff0ffe9dd781938b0de
8: (peer_ip): 10.0.0.7
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:39:04.023783
11: (prefix): 100.100.100.0
12: (prefix_len): 24
13: (is_ipv4): 1
14: (origin): incomplete
15: (as_path):
16: (as_path_count): 0
17: (origin_as): 0
18: (nexthop): 10.0.0.7
19: (med): 0
20: (local_pref): 100
21: (aggregator):
22: (community_list):
23: (ext_community_list): rt=100:100
24: (cluster_list):
25: (isatomicagg): 0
26: (is_nexthop_ipv4): 1
27: (originator_id):
28: (path_id): 0
29: (labels): 24000
30: (is_prepolicy): 1
31: (is_adj_rib_in): 1
32: (vpn_rd): 100100:100
33: (vpn_rd_type): 0

// delete l3vpn (prefix) message

1: (action): del
2: (sequence): 34
3: (hash): 332047c6ca64451ed6f5ddb92710a29a
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (router_ip): 10.1.34.1
6: (base_attr_hash):
7: (peer_hash): d67b274c33ea1ff0ffe9dd781938b0de
8: (peer_ip): 10.0.0.7
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:37:53.516968
11: (prefix): 100.100.100.0
12: (prefix_len): 24
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
29: (labels): 524288
30: (is_prepolicy): 1
31: (is_adj_rib_in): 1
32: (vpn_rd): 100100:100
33: (vpn_rd_type): 0

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
26: (is_prepolicy):
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
### SRv6 L3VPN Message (v4 overlay, SRv6 underlay)

```
// add (l3vpn (prefix) message - it appears openbmp is not sure what to do with much of this message.  See bgp show command output below

1: (action): add
2: (sequence): 38
3: (hash): b44a84e415927f20ff3e6edf7103875c
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (router_ip): 10.1.34.1
6: (base_attr_hash): e0895cf0bc3391438d43cdc7e43aae36
7: (peer_hash): 0146fce99cbd730d787487de31452f88
8: (peer_ip): 2001:1:1:f003::1                        // this is ok
9: (peer_asn): 100000                                 // this is ok
10: (timestamp): 2020-03-25 22:41:32.861004
11: (prefix): 0.0.0.0                                 // should be 3.30.30.0/24
12: (prefix_len): 0
13: (is_ipv4): 1
14: (origin): incomplete
15: (as_path):
16: (as_path_count): 0
17: (origin_as): 0
18: (nexthop): 32.1.0.1                               // wrong
19: (med): 0
20: (local_pref): 100
21: (aggregator):
22: (community_list):
23: (ext_community_list): rt=300:10                   // this is ok
24: (cluster_list):
25: (isatomicagg): 0
26: (is_nexthop_ipv4): 1
27: (originator_id):
28: (path_id): 0
29: (labels): 1072,0                                  // VPN label should be replaced with SRv6-VPN SID: 2001:1:1:f003:43::/128
30: (is_prepolicy): 1
31: (is_adj_rib_in): 1
32: (vpn_rd): 1679764780:167976478                    // ? should be 300:10
33: (vpn_rd_type): 0

// show BGP command output for the above SRv6 l3vpn message:

RP/0/RP0/CPU0:R04#sho bgp vrf alpha 3.30.30.0/24 det
Wed Mar 25 22:50:24.005 UTC
BGP routing table entry for 3.30.30.0/24, Route Distinguisher: 300:10
Versions:
  Process           bRIB/RIB  SendTblVer
  Speaker                 73          73
    Flags: 0x00041001+0x00000000;
Last Modified: Mar 25 22:41:21.141 for 00:09:05
Paths: (1 available, best #1)
  Not advertised to any peer
  Path #1: Received by speaker 0
  Flags: 0x4000000085060005, import: 0x9f
  Not advertised to any peer
  Local
    2001:1:1:f003::1 (metric 1) from 2001:1:1:f010::1 (10.0.0.3), if-handle 0x00000000
      Received Label 17152
      Origin incomplete, metric 0, localpref 100, valid, internal, best, group-best, import-candidate, imported
      Received Path ID 0, Local Path ID 1, version 73
      Extended community: RT:300:10
      Originator: 10.0.0.3, Cluster list: 10.0.0.10
      PSID-Type:L3, SubTLV Count:1, R:0x00,
       SubTLV:
        T:1(Sid information), Sid:2001:1:1:f003::, F:0x00, R2:0x00, Behavior:65535, R3:0x00, SS-TLV Count:1
         SubSubTLV:
          T:1(Sid structure):
           Length [Loc-blk,Loc-node,Func,Arg]:[40,24,16,0], Tpose-len:16, Tpose-offset:64
      Source AFI: VPNv4 Unicast, Source VRF: alpha, Source Route Distinguisher: 300:10

// show cef command output for the above entry:

RP/0/RP0/CPU0:R04#sho cef vrf alpha 3.30.30.0/24 det
Wed Mar 25 22:52:03.008 UTC
3.30.30.0/24, version 29, SRv6 Transit, internal 0x5000001 0x0 (ptr 0xdf182a4) [1], 0x0 (0xe0e81a8), 0x0 (0xf17f228)
 Updated Mar 25 22:41:20.806
 Prefix Len 24, traffic index 0, precedence n/a, priority 3
  gateway array (0xf4aa0a8) reference count 2, flags 0x10, source rib (7), 0 backups
                [3 type 3 flags 0x8441 (0xe001728) ext 0x0 (0x0)]
  LW-LDI[type=3, refc=1, ptr=0xe0e81a8, sh-ldi=0xe001728]
  gateway array update type-time 1 Mar 18 14:37:27.144
 LDI Update time Mar 18 14:37:27.187
 LW-LDI-TS Mar 25 22:41:20.813

  Level 1 - Load distribution: 0
  [0] via 2001:1:1:f003::/128, recursive

   via 2001:1:1:f003::/128, 3 dependencies, recursive [flags 0x6000]
    path-idx 0 NHID 0x0 [0xe247894 0x0]
    next hop VRF - 'default', table - 0xe0800000
    next hop 2001:1:1:f003::/128 via 2001:1:1:f003::/64
    SRv6 T.Encaps.Red SID-list {2001:1:1:f003:43::}

    Load distribution: 0 (refcount 3)

    Hash  OK  Interface                 Address
    0     Y   GigabitEthernet0/0/0/0    remote


// delete l3vpn (prefix) message

1: (action): del
2: (sequence): 37
3: (hash): 2f358ba42cb0a8a00c210b0accbf1af4
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (router_ip): 10.1.34.1
6: (base_attr_hash):
7: (peer_hash): 0146fce99cbd730d787487de31452f88
8: (peer_ip): 2001:1:1:f003::1
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 22:41:03.602687
11: (prefix): 3.30.30.0
12: (prefix_len): 24
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
29: (labels): 524288
30: (is_prepolicy): 1
31: (is_adj_rib_in): 1
32: (vpn_rd): 10300:10
33: (vpn_rd_type): 0
