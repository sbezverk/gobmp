package arangodb

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	driver "github.com/arangodb/go-driver"
	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/message"
	"github.com/sbezverk/gobmp/pkg/srv6"
	"golang.org/x/sync/semaphore"
)

const (
	l3prefix = "L3VPN_Prefix"
	l3vpnrt  = "L3VPN_RT"
)

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

var sem = semaphore.NewWeighted(int64(1))

func (a *arangoDB) l3vpnHandler(obj *message.L3VPNPrefix) {
	ctx := context.TODO()
	sem.Acquire(ctx, 1)
	defer sem.Release(1)
	// adb := a.GetArangoDBInterface()
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
	var oldPrefix L3VPNPrefix
	if ok {
		_, err := prc.ReadDocument(ctx, k, &oldPrefix)
		if err != nil {
			glog.Errorf("failed to read existing document %s with error: %+v", k, err)
			return
		}
	}
	switch obj.Action {
	case "add":
		if ok {
			// Document by the key already exists, hence updating it
			if _, err := prc.UpdateDocument(ctx, k, r); err != nil {
				glog.Errorf("failed to update document %s with error: %+v", k, err)
				return
			}
			// Update route targets collection with references to the updated prefix
			if err := processRouteTargets(ctx, rtc, &oldPrefix, r); err != nil {
				glog.Errorf("failed to update the route target collection %s with reference to %s with error: %+v", rtc.Name(), k, err)
				return
			}
		}
		if _, err := prc.CreateDocument(ctx, r); err != nil {
			glog.Errorf("failed to create document %s with error: %+v", k, err)
			return
		}
		// Add route targets collection with references to the added prefix
		if err := processRouteTargets(ctx, rtc, nil, r); err != nil {
			glog.Errorf("failed to add to the route target collection %s references for %s with error: %+v", rtc.Name(), k, err)
			return
		}
	case "del":
		if ok {
			// Document by the key exists, hence delete it
			if _, err := prc.RemoveDocument(ctx, k); err != nil {
				glog.Errorf("failed to delete document %s with error: %+v", k, err)
				return
			}
			// Clean up route targets collection from references to the deleted prefix
			if err := processRouteTargets(ctx, rtc, &oldPrefix, nil); err != nil {
				glog.Errorf("failed to clean up the route target collection %s from references to %s with error: %+v", rtc.Name(), k, err)
				return
			}
		}
	}
}

func processRouteTargets(ctx context.Context, rtc driver.Collection, o, n *L3VPNPrefix) error {
	if o == nil && n == nil {
		return nil
	}
	if o == nil && n != nil {
		// New prefix was added, adding references to its route targets if any
		if err := addPrefixRT(ctx, rtc, n.ID, n.Key, n.ExtComm); err != nil {
			return err
		}
		return nil
	}
	if o != nil && n == nil {
		// Existing prefix was delete, remove references from all route targets if any
		if err := deletePrefixRT(ctx, rtc, o.ID, o.Key, o.ExtComm); err != nil {
			return err
		}
		return nil
	}
	// Existing prefix was updated, update route target references if any
	return nil
}

func addPrefixRT(ctx context.Context, rtc driver.Collection, id, key string, extComm []string) error {
	for _, ext := range extComm {
		if !strings.HasPrefix(ext, "rt=") {
			continue
		}
		rt := strings.TrimPrefix(ext, "rt=")
		// glog.Infof("for prefix key: %s found route target: %s", key, rt)
		found, err := rtc.DocumentExists(ctx, rt)
		if err != nil {
			return err
		}
		if found {
			glog.Infof("route target: %s exists in rt collection %s", rt, rtc.Name())
			rtr := &L3VPNRT{}
			_, err := rtc.ReadDocument(ctx, rt, rtr)
			if err != nil {
				glog.Errorf("read doc error: %+v", err)
				return err
			}
			if _, ok := rtr.Prefixes[id]; ok {
				continue
			}

			rtr.Prefixes[id] = key
			_, err = rtc.UpdateDocument(ctx, rt, rtr)
			if err != nil {
				glog.Errorf("update doc error: %+v", err)
				return err
			}
			continue
		}
		rtr := &L3VPNRT{
			ID:  rtc.Name() + "/" + rt,
			Key: rt,
			RT:  rt,
			Prefixes: map[string]string{
				id: key,
			},
		}
		glog.V(5).Infof("route target: %s does not exist in rt collection %s id: %s", rt, rtc.Name(), rtr.ID)
		if _, err := rtc.CreateDocument(ctx, rtr); err != nil {
			glog.Errorf("create doc error: %+v", err)
			return err
		}
	}

	return nil
}

func deletePrefixRT(ctx context.Context, rtc driver.Collection, id, key string, extComm []string) error {
	var mtx sync.Mutex
	mtx.Lock()
	for _, ext := range extComm {
		if !strings.HasPrefix(ext, "rt=") {
			continue
		}
		rt := strings.TrimPrefix(ext, "rt=")
		// glog.Infof("for prefix key: %s found route target: %s", key, rt)
		found, err := rtc.DocumentExists(ctx, rt)
		if err != nil {
			return err
		}
		if found {
			glog.Infof("route target: %s exists in rt collection %s", rt, rtc.Name())
			rtr := &L3VPNRT{}
			_, err := rtc.ReadDocument(ctx, rt, rtr)
			if err != nil {
				glog.Errorf("read doc error: %+v", err)
			}
			if _, ok := rtr.Prefixes[id]; !ok {
				continue
			}
			delete(rtr.Prefixes, id)
			// Check If route target document has any references to other prefixes, if no, then deleting
			// Route Target document, otherwise updating it
			if len(rtr.Prefixes) == 0 {
				_, err := rtc.RemoveDocument(ctx, rt)
				if err != nil {
					glog.Errorf("failed to delete empty route target %s with error: %+v", rt, err)
				}
				continue
			}
			b, err := json.Marshal(rtr)
			if err != nil {
				glog.Errorf("marshal error: %+v", err)
				return err
			}
			glog.Infof("resulting RT record: %s", string(b))
			if _, err := rtc.UpdateDocument(ctx, rt, rtr); err != nil {
				glog.Errorf("update doc error: %+v", err)
				return err
			}
		}
	}

	return nil
}
