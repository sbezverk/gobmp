# BGP Monitoring Protocol (BMP)

https://tools.ietf.org/html/rfc7854

## BMP message types and GoBMP:
GoBMP will not need to collect and parse the following BMP message types:
collector - not used
router - not currently used
bmp_stat - not used
base attribute - not used

GoBMP will not need to collect and parse the following BMP message types (details below):
peer
unicast_prefix 
ls_node
ls_link
ls_prefix
l3vpn
evpn

### BMP peer message:
1: (action): up/down
5: (name): 
6: (remote_bgp_id): 
7: (router_ip): 
8: (timestamp): 
9: (remote_asn): 
10: (remote_ip): 
11: (peer_rd): 
13: (local_asn): 
14: (local_ip): 
16: (local_bgp_id):
18: (adv_cap): MPBGP (1) : afi=2 safi=1 : Unicast IPv6, Route Refresh Old (128), Route Refresh (2), 4 Octet ASN (65), 5
19: (recv_cap): MPBGP (1) : afi=2 safi=1 : Unicast IPv6, Route Refresh Old (128), Route Refresh (2), Route Refresh Enhanced (70), 4 Octet ASN (65) 
26: (is_l3vpn): 
27: (isprepolicy): 
28: (is_ipv4): 
29: (is_locrib): 
30: (is_locrib_filtered): 
31: (table_name): 

### BMP ls_node message:
1: (action): add/del
6: (router_ip): 
8: (peer_ip): 
9: (peer_asn):
10: (timestamp): 
11: (igp_router_id): 
12: (router_id): 
14: (ls_id): 
15: (mt_id): 
17: (isis_area_id): 
18: (protocol): 
19: (flags): 
20: (as_path): 
21: (local_pref): 
22: (med): 
23: (nexthop): 
24: (name): 
25: (isprepolicy): 
26: (is_adj_rib_in): 
27: (ls_sr_capabilities):


