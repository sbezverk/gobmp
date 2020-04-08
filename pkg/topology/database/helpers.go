package database

import (
	"fmt"
)

func (a *ArangoConn) GetSIDIndex(ip string) string {
        if len(ip) == 0 {
                return ""
        }
        var r string
        q := fmt.Sprintf("FOR r in Routers FILTER r.BGPID == %q AND r.NodeSIDIndex != null RETURN r.NodeSIDIndex", ip)
        results, _ := a.Query(q, nil, r)
        if len(results) > 0 {
                sid_index := results[len(results)-1].(string)
		return sid_index
        }
        return ""
}


func (a *ArangoConn) CheckExistingEPENode(local_bgp_id string) bool {
    var r string
    q := fmt.Sprintf("FOR r in EPENode filter r._key == %q return r", local_bgp_id)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        return true
    } else {
        return false
    }
}

func (a *ArangoConn) GetExistingPeerIP(local_bgp_id string) []string {
    var r string
    var tmp []string
    q := fmt.Sprintf("FOR r in EPENode filter r._key == %q return r.PeerIP", local_bgp_id)
    results, _ := a.Query(q, nil, r)
    fmt.Println("Beginning debugging")
    fmt.Println(results)
    fmt.Printf("%T\n", results)
    if len(results) > 0 {
        fmt.Println(results[0])
        fmt.Println(results[0].(string))

    } else {
        fmt.Println(results)
    }
    return tmp
}

func (a *ArangoConn) UpdateExistingPeerIP(local_bgp_id string, peer_ip string) {
    var r string
    q := fmt.Sprintf("For e in EPENode Filter e._key == %q LET p = e.PeerIP UPDATE { _key: e._key, PeerIP: APPEND(p, %q, True) } IN EPENode RETURN { before: OLD, after: NEW }", local_bgp_id, peer_ip)
    //q := fmt.Sprintf("LET doc = DOCUMENT(%q) UPDATE doc WITH { RD: PUSH(doc.RD, %q)} IN EPENode", router_id, peer_ip)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        fmt.Printf("Successfully updated EPENode peer list with %q for Router %q\n", peer_ip, local_bgp_id)
    } else {
        fmt.Println("Something went wrong -- failed to update peer ip")
    }
}

func (a *ArangoConn) CheckExistingL3VPNRouter(router_ip string) bool {
    var r string
    q := fmt.Sprintf("FOR r in L3VPN_Routers filter r._key == %q return r", router_ip)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        return true
    } else {
        return false
    }
}

func (a *ArangoConn) CheckExistingL3VPNNode(router_ip string) bool {
    var r string
    q := fmt.Sprintf("FOR r in L3VPNNode filter r._key == %q return r", router_ip)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        return true
    } else {
        return false
    }
}

func (a *ArangoConn) GetExistingVPNRDS(router_ip string) []string {
    var r string
    var tmp []string
    q := fmt.Sprintf("FOR r in L3VPNNode filter r._key == %q return r.RD", router_ip)
    results, _ := a.Query(q, nil, r)
    fmt.Println("Beginning debugging")
    fmt.Println(results)
    fmt.Printf("%T\n", results)
    if len(results) > 0 {
        fmt.Println(results[0])
        //fmt.Println(results[0].(string))

    } else {
        fmt.Println(results)
    }
    return tmp
}


func (a *ArangoConn) UpdateExistingVPNRDS(router_ip string, vpn_rd string) {
    var r string
    q := fmt.Sprintf("For e in L3VPNNode Filter e._key == %q LET p = e.RD UPDATE { _key: e._key, RD: APPEND(p, %q, True) } IN L3VPNNode RETURN { before: OLD, after: NEW }", router_ip, vpn_rd)
    //q := fmt.Sprintf("LET doc = DOCUMENT(%q) UPDATE doc WITH { RD: PUSH(doc.RD, %q)} IN L3VPN_Routers", router_ip, vpn_rd)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        fmt.Printf("Successfully updated VPN RD list with %q for Router %q\n", vpn_rd, router_ip)
    } else {
        fmt.Println("Something went wrong -- failed to update VPN RD")
    }

}


func (a *ArangoConn) CreateAdjacencyList(key string, adjacency_sid string, flags string, weight string) {
    var r string
    fmt.Println(key, adjacency_sid, flags, weight)
    doc_key := "LSLink/" + key
    q := fmt.Sprintf("LET doc = DOCUMENT(%q) UPDATE doc WITH { Adjacencies: PUSH(doc.Adjacencies, {adjacency_sid:%q, flags:%q, weight:%q}, True) } IN LSLink RETURN { before: OLD, after: NEW }", doc_key, adjacency_sid, flags, weight)
    results, _ := a.Query(q, nil, r)
    if len(results) > 0 {
        fmt.Printf("Successfully updated Adjacency List with %q for Link %q\n", adjacency_sid, key)
    } else {
        fmt.Println("Something went wrong -- failed to update adjacency_list")
    }
}

