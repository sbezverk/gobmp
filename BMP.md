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

#### BMP peer message:
```
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
```

#### BMP unicast_prefix message:
```
1: (action): add
2: (sequence): 0
3: (hash): 8b5fab47bba7746283b619dd3e0e83af
4: (router_hash): fb5d34c594dff80c59019b6d132185f7
5: (router_ip): 10.1.34.1
6: (base_attr_hash): 53d35d1295d2c2e6b9f71c20b3577fc6
7: (peer_hash): a8c7c8886de02687b172b63aaab0e21c
8: (peer_ip): 10.0.0.9
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 09:18:45.347819
11: (prefix): 10.0.0.9
12: (prefix_len): 32
13: (is_ipv4): 1
14: (origin): igp
15: (as_path): 
16: (as_path_count): 0
17: (origin_as): 0
18: (nexthop): 10.0.0.9
19: (med): 0
20: (local_pref): 100
21: (aggregator): 
22: (community_list): 
23: (ext_community_list): 
24: (cluster_list): 
25: (isatomicagg): 0
26: (is_nexthop_ipv4): 1
27: (originator_id): 
28: (path_id): 1
29: (labels): 3
30: (isprepolicy): 1
31: (is_adj_rib_in): 1
```

#### BMP ls_node message:
```
1: (action): add
2: (sequence): 1
3: (hash): 480f4dc02dfe6f2bc5ec84cdcde59a79
4: (base_attr_hash): 56ec192668fdb134ac185c3619e017d7
5: (router_hash): fb5d34c594dff80c59019b6d132185f7
6: (router_ip): 10.1.34.1
7: (peer_hash): 6b34d1284927fc86a5c9768df7ce76ec
8: (peer_ip): 10.0.0.1
9: (peer_asn): 100000
10: (timestamp): 2020-03-25 09:18:45.509368
11: (igp_router_id): 0000.0000.0006.0000
12: (router_id): 10.0.0.6
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
24: (name): R06
25: (isprepolicy): 1
26: (is_adj_rib_in): 1
27: (ls_sr_capabilities): I 64000 100000

Additional segment routing and SRv6 items not accounted for by OpenBMP:

BGP-LS TLV Type: 1035 (SR Algorithm) - int (i think)
BGP-LS TLV Type: 1036 (SR Local Block) - might arrive as a pair of integers
BGP-LS TLV Type: 1038 (SRv6 Capabilities TLV) - string

```
#### BMP ls_link message:
```
1: (action): add/del
2: (sequence): 115
6: (router_ip):
8: (peer_ip): 
9: (peer_asn): 
10: (timestamp):
11: (igp_router_id):
12: (router_id):
14: (ls_id): 
16: (isis_area_id): 
17: (protocol):
18: (as_path): 
19: (local_pref): 
20: (med): 
21: (nexthop):
22: (mt_id): 
23: (local_link_id): 
24: (remote_link_id): 
25: (intf_ip): 
26: (nei_ip): 
27: (igp_metric): 
28: (admin_group): 
29: (max_link_bw): 
30: (max_resv_bw):
31: (unresv_bw): 
32: (te_default_metric): 
33: (link_protection): 
34: (mpls_proto_mask): 
35: (srlg): 
36: (link_name): 
39: (remote_igp_router_id): 
40: (remote_router_id): 
41: (local_node_asn): 
42: (remote_node_asn): 
43: (peer_node_sid): 
44: (isprepolicy): 
45: (is_adj_rib_in): 
46: (ls_adjacency_sid): 

Additional segment routing and SRv6 items not accounted for by OpenBMP:


```
#### BMP ls_prefix message:

```
1: (action): add/del
6: (router_ip): 
8: (peer_ip): 
9: (peer_asn): 
10: (timestamp): 
11: (igp_router_id): 
12: (router_id): 
14: (ls_id): 
16: (isis_area_id): 
17: (protocol): 
18: (as_path): 
19: (local_pref): 
20: (med): 
21: (nexthop):
23: (mt_id): 
25: (igp_flags): 
26: (route_tag): 
27: (ext_route_tag): 
29: (igp_metric): 
30: (prefix): 
31: (prefix_len): 
32: (isprepolicy): 
33: (is_adj_rib_in): 
34: (ls_prefix_sid): 

Additional segment routing and SRv6 items not accounted for by OpenBMP:

```
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
