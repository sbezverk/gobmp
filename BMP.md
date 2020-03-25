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
1: (action): string (up/down)
5: (name): 
6: (remote_bgp_id): 
7: (router_ip): 
8: (timestamp): 
9: (remote_asn): int
10: (remote_ip): 
11: (peer_rd): 
13: (local_asn): int
14: (local_ip): 
16: (local_bgp_id):
18: (adv_cap): MPBGP (1) : afi=2 safi=1 : Unicast IPv6, Route Refresh Old (128), Route Refresh (2), 4 Octet ASN (65), 5
19: (recv_cap): MPBGP (1) : afi=2 safi=1 : Unicast IPv6, Route Refresh Old (128), Route Refresh (2), Route Refresh Enhanced (70), 4 Octet ASN (65) 
26: (is_l3vpn): bool
27: (isprepolicy): bool
28: (is_ipv4): bool
29: (is_locrib): bool
30: (is_locrib_filtered): bool
31: (table_name): 
```

#### BMP unicast_prefix message:
```
1: (action): string (add/del)
5: (router_ip): 
8: (peer_ip): 
9: (peer_asn): int
10: (timestamp): 2020-03-19 16:04:33.296556
11: (prefix):
12: (prefix_len): int
13: (is_ipv4): bool
14: (origin): 
15: (as_path): list of integers
16: (as_path_count): int
17: (origin_as): int
18: (nexthop): 
19: (med): int
20: (local_pref): int
22: (community_list): 
23: (ext_community_list): 
24: (cluster_list): 
25: (isatomicagg): bool
26: (is_nexthop_ipv4): bool
27: (originator_id): 
28: (path_id): int
29: (labels): 
30: (isprepolicy): int
31: (is_adj_rib_in): int
```

#### BMP ls_node message:
```
1: (action): string (add/del)
6: (router_ip): 
8: (peer_ip): 
9: (peer_asn): int
10: (timestamp): 
11: (igp_router_id): 
12: (router_id): 
14: (ls_id): int
15: (mt_id): 
17: (isis_area_id): 
18: (protocol): 
19: (flags): 
20: (as_path): 
21: (local_pref): int
22: (med): int
23: (nexthop): 
24: (name): 
25: (isprepolicy): bool
26: (is_adj_rib_in): bool
27: (ls_sr_capabilities):

Additional segment routing and SRv6 items not accounted for by OpenBMP:

BGP-LS TLV Type: 1035 (SR Algorithm) - int (i think)
BGP-LS TLV Type: 1036 (SR Local Block) - 
BGP-LS TLV Type: 1038 (SRv6 Capabilities TLV)

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
