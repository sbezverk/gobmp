package arangodb

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	driver "github.com/arangodb/go-driver"
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"github.com/sbezverk/gobmp/pkg/topology/locker"
)

const (
	l3prefix = "L3VPN_Prefix"
	l3vpnrt  = "L3VPN_RT"
)

var mtx = sync.Mutex{}

// L3VPNPrefix represents the database record structure for L3VPN Prefix collection
type L3VPNPrefix struct {
	Key       string          `json:"_key,omitempty"`
	ID        string          `json:"_id,omitempty"`
	Rev       string          `json:"_rev,omitempty"`
	Prefix    string          `json:"Prefix,omitempty"`
	PrefixLen int32           `json:"Length,omitempty"`
	IsIPv4    bool            `json:"IPv4"`
	OriginAS  int32           `json:"ASN,omitempty"`
	Nexthop   string          `json:"RouterID,omitempty"`
	Labels    []uint32        `json:"VPN_Label,omitempty"`
	RD        string          `json:"RD,omitempty"`
	ExtComm   []string        `json:"ExtComm,omitempty"`
	SRv6SID   *srv6.L3Service `json:"SRv6_SID,omitempty"`
}

// L3VPNRT defines route target record
type L3VPNRT struct {
	ID       string            `json:"_id,omitempty"`
	Key      string            `json:"_key,omitempty"`
	Rev      string            `json:"_rev,omitempty"`
	RT       string            `json:"RT,omitempty"`
	Prefixes map[string]string `json:"Prefixes,omitempty"`
}

func (a *arangoDB) l3vpnHandler(obj *message.L3VPNPrefix) {
	ctx := context.TODO()
	if obj == nil {
		glog.Warning("L3 VPN Prefix object is nil")
		return
	}
	k := obj.VPNRD + "_" + obj.Prefix + "_" + strconv.Itoa(int(obj.PrefixLen))
	r := &L3VPNPrefix{
		Key:       k,
		ID:        l3prefix + "/" + k,
		Prefix:    obj.Prefix,
		PrefixLen: obj.PrefixLen,
		IsIPv4:    obj.IsIPv4,
		OriginAS:  obj.OriginAS,
		Nexthop:   obj.Nexthop,
		Labels:    obj.Labels,
		RD:        obj.VPNRD,
		ExtComm:   obj.BaseAttributes.ExtCommunityList,
	}

	if obj.PrefixSID != nil {
		r.SRv6SID = obj.PrefixSID.SRv6L3Service
	}

	var prc driver.Collection
	var rtc driver.Collection
	var err error
	if prc, err = a.ensureCollection(l3prefix); err != nil {
		glog.Errorf("failed to ensure for collection %s with error: %+v", l3prefix, err)
		return
	}
	if rtc, err = a.ensureCollection(l3vpnrt); err != nil {
		glog.Errorf("failed to ensure for collection %s with error: %+v", l3prefix, err)
		return
	}
	ok, err := prc.DocumentExists(ctx, k)
	if err != nil {
		glog.Errorf("failed to check for document %s with error: %+v", k, err)
		return
	}

	switch obj.Action {
	case "add":
		if ok {
			glog.Infof("Add for existing prefix: %s", k)
			// Document by the key already exists, hence reading previous version of the document first
			// and then updating it
			var o L3VPNPrefix
			_, err := prc.ReadDocument(ctx, k, &o)
			if err != nil {
				glog.Errorf("failed to read existing document %s with error: %+v", k, err)
				return
			}
			if _, err := prc.UpdateDocument(ctx, k, r); err != nil {
				glog.Errorf("failed to update document %s with error: %+v", k, err)
				return
			}
			// Update route targets collection with references to the updated prefix
			if err := processRouteTargets(ctx, a.lckr, rtc, &o, r); err != nil {
				glog.Errorf("failed to update the route target collection %s with reference to %s with error: %+v", rtc.Name(), k, err)
				return
			}
			// All good, the document was updated and processRouteTargets succeeded, returning...
			return
		}
		glog.Infof("Add for non-existing prefix: %s", k)
		if _, err := prc.CreateDocument(ctx, r); err != nil {
			glog.Errorf("failed to create document %s with error: %+v", k, err)
			return
		}
		// Add route targets collection with references to the added prefix
		if err := processRouteTargets(ctx, a.lckr, rtc, nil, r); err != nil {
			glog.Errorf("failed to add to the route target collection %s references for %s with error: %+v", rtc.Name(), k, err)
			return
		}
	case "del":
		if ok {
			glog.Infof("Delete for existing prefix: %s", k)
			// Document by the key exists, hence delete it
			if _, err := prc.RemoveDocument(ctx, k); err != nil {
				glog.Errorf("failed to delete document %s with error: %+v", k, err)
				return
			}
			// Clean up route targets collection from references to the deleted prefix
			if err := processRouteTargets(ctx, a.lckr, rtc, r, nil); err != nil {
				glog.Errorf("failed to clean up the route target collection %s from references to %s with error: %+v", rtc.Name(), k, err)
				return
			}
			return
		}
		glog.Warningf("Delete for non-existing prefix: %s", k)
	}
}

func processRouteTargets(ctx context.Context, lckr locker.Locker, rtc driver.Collection, o, n *L3VPNPrefix) error {
	if o == nil && n == nil {
		return nil
	}
	if o == nil && n != nil {
		// New prefix was added, adding references to its route targets if any
		if err := addPrefixRT(ctx, lckr, rtc, n.ID, n.Key, n.ExtComm); err != nil {
			return err
		}
		return nil
	}
	if o != nil && n == nil {
		// Existing prefix was delete, remove references from all route targets if any
		if err := deletePrefixRT(ctx, lckr, rtc, o.ID, o.Key, o.ExtComm); err != nil {
			return err
		}
		return nil
	}
	// Existing prefix was updated, update route target references if any
	toAdd, toDel := ExtCommGetDiff(bgp.ECPRouteTarget, o.ExtComm, n.ExtComm)
	if len(toAdd) != 0 {
		if err := addPrefixRT(ctx, lckr, rtc, n.ID, n.Key, toAdd); err != nil {
			return err
		}
	}
	if len(toDel) != 0 {
		if err := deletePrefixRT(ctx, lckr, rtc, n.ID, n.Key, toDel); err != nil {
			return err
		}
	}

	return nil
}

func addPrefixRT(ctx context.Context, lckr locker.Locker, rtc driver.Collection, id, key string, extComm []string) error {
	for _, ext := range extComm {
		if !strings.HasPrefix(ext, bgp.ECPRouteTarget) {
			continue
		}
		rt := strings.TrimPrefix(ext, bgp.ECPRouteTarget)
		if err := processRTAdd(ctx, lckr, rtc, id, key, rt); err != nil {
			return err
		}

	}

	return nil
}

func deletePrefixRT(ctx context.Context, lckr locker.Locker, rtc driver.Collection, id, key string, extComm []string) error {
	for _, ext := range extComm {
		if !strings.HasPrefix(ext, bgp.ECPRouteTarget) {
			continue
		}
		rt := strings.TrimPrefix(ext, bgp.ECPRouteTarget)
		if err := processRTDel(ctx, lckr, rtc, id, key, rt); err != nil {
			return err
		}

	}

	return nil
}

func processRTAdd(ctx context.Context, lckr locker.Locker, rtc driver.Collection, id, key, rt string) error {
	lckr.Lock(rt)
	defer func() {
		lckr.Unlock(rt)
	}()

	found, err := rtc.DocumentExists(ctx, rt)
	if err != nil {
		return err
	}
	rtr := &L3VPNRT{}
	nctx := driver.WithWaitForSync(ctx)
	if found {
		mtx.Lock()
		_, err := rtc.ReadDocument(nctx, rt, rtr)
		mtx.Unlock()
		if err != nil {
			return err
		}
		if _, ok := rtr.Prefixes[id]; ok {
			return nil
		}
		mtx.Lock()
		rtr.Prefixes[id] = key
		_, err = rtc.UpdateDocument(nctx, rt, rtr)
		mtx.Unlock()
		if err != nil {
			return err
		}
		return nil
	}
	rtr.ID = rtc.Name() + "/" + rt
	rtr.Key = rt
	rtr.RT = rt
	rtr.Prefixes = map[string]string{
		id: key,
	}
	if _, err := rtc.CreateDocument(nctx, rtr); err != nil {
		return err
	}
	return nil
}

func processRTDel(ctx context.Context, lckr locker.Locker, rtc driver.Collection, id, key, rt string) error {
	lckr.Lock(rt)
	defer func() {
		lckr.Unlock(rt)
	}()

	found, err := rtc.DocumentExists(ctx, rt)
	if err != nil {
		return err
	}
	rtr := &L3VPNRT{}
	nctx := driver.WithWaitForSync(ctx)
	if found {
		mtx.Lock()
		_, err := rtc.ReadDocument(nctx, rt, rtr)
		mtx.Unlock()
		if err != nil {
			return err
		}
		if _, ok := rtr.Prefixes[id]; !ok {
			return nil
		}
		delete(rtr.Prefixes, id)
		// Check If route target document has any references to other prefixes, if no, then deleting
		// Route Target document, otherwise updating it
		if len(rtr.Prefixes) == 0 {
			glog.Infof("RT with key %s has no more entries, deleting it...", rt)
			mtx.Lock()
			_, err := rtc.RemoveDocument(ctx, rt)
			mtx.Unlock()
			if err != nil {
				return fmt.Errorf("failed to delete empty route target %s with error: %+v", rt, err)
			}
			return nil
		}
		mtx.Lock()
		_, err = rtc.UpdateDocument(nctx, rt, rtr)
		mtx.Unlock()
		if err != nil {
			return err
		}
	}

	return nil
}

// ExtCommGetDiff checks two sets of extended communities for differences and returns two slices.
// First slice (toAdd) carries items which were not in the old but are in the new, second
// slice carries items which were in old but absent in the new.
// extCommType carries a prefix of a particular type of extended community,
// see github.com/sbezverk/gobmp/pkg/bgp/extended-community.gp for definitions.
func ExtCommGetDiff(extCommType string, old, new []string) ([]string, []string) {
	toDel := diffSlice(extCommType, old, new)
	toAdd := diffSlice(extCommType, new, old)

	return toAdd, toDel
}

func diffSlice(prefix string, s1, s2 []string) []string {
	diff := make([]string, 0)
	for i, s1e := range s1 {
		found := false
		if !strings.HasPrefix(s1e, prefix) {
			continue
		}
		// oe = strings.TrimPrefix(oe, extCommType)
		for _, s2e := range s2 {
			if !strings.HasPrefix(s2e, prefix) {
				continue
			}
			// ne = strings.TrimPrefix(ne, extCommType)
			if strings.Compare(s1e, s2e) == 0 {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, s1[i])
		}
	}

	return diff
}
