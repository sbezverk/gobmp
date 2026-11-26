package message

import (
	"encoding/binary"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// pathIDReaders decode b into each message type that publishes path_id
// unsigned, starting from a value with PathID 5, and return the decoded
// PathID and prefix.
var pathIDReaders = map[string]func(b []byte) (uint32, string, error){
	"UnicastPrefix": func(b []byte) (uint32, string, error) {
		m := UnicastPrefix{PathID: 5}
		err := json.Unmarshal(b, &m)
		return m.PathID, m.Prefix, err
	},
	"MulticastPrefix": func(b []byte) (uint32, string, error) {
		m := MulticastPrefix{PathID: 5}
		err := json.Unmarshal(b, &m)
		return m.PathID, m.Prefix, err
	},
	"MUPPrefix": func(b []byte) (uint32, string, error) {
		m := MUPPrefix{PathID: 5}
		err := json.Unmarshal(b, &m)
		return m.PathID, m.Prefix, err
	},
	"L3VPNPrefix": func(b []byte) (uint32, string, error) {
		m := L3VPNPrefix{PathID: 5}
		err := json.Unmarshal(b, &m)
		return m.PathID, m.Prefix, err
	},
}

// TestPathIDJSONReadsSignedAndUnsigned checks that every reader maps the
// signed path_id published before it became uint32 and the unsigned one to
// the same RFC 7911 Path Identifier, and rejects values outside 32 bits.
func TestPathIDJSONReadsSignedAndUnsigned(t *testing.T) {
	accepted := []struct {
		json string
		want uint32
	}{
		{`0`, 0},
		{`2147483647`, 1<<31 - 1},
		{`-2147483648`, 1 << 31},
		{`2147483648`, 1 << 31},
		{`-1`, ^uint32(0)},
		{`4294967295`, ^uint32(0)},
		{`null`, 5}, // left unchanged, as for any JSON null
	}
	rejected := []string{`-2147483649`, `4294967296`, `1.5`, `"7"`, `true`}
	for name, read := range pathIDReaders {
		t.Run(name, func(t *testing.T) {
			for _, tc := range accepted {
				id, prefix, err := read([]byte(`{"prefix":"10.1.2.0","path_id":` + tc.json + `}`))
				if err != nil || id != tc.want || prefix != "10.1.2.0" {
					t.Errorf("path_id %s: got %d %q %v, want %d \"10.1.2.0\" nil", tc.json, id, prefix, err, tc.want)
				}
			}
			if id, _, err := read([]byte(`{"prefix":"10.1.2.0"}`)); err != nil || id != 5 {
				t.Errorf("absent path_id: got %d %v, want 5 nil", id, err)
			}
			for _, v := range rejected {
				if _, _, err := read([]byte(`{"path_id":` + v + `}`)); err == nil {
					t.Errorf("path_id %s: no error", v)
				}
			}
		})
	}
}

// TestPathIDRouteStoreAcrossVersions replays route events through a store
// keyed by the JSON hash, as a consumer would, mixing events recorded while
// path_id was signed with events published now. Each announcement must be
// removed by the other version's withdrawal, in both directions.
func TestPathIDRouteStoreAcrossVersions(t *testing.T) {
	v4Prefix := []byte{0x18, 0x0a, 0x01, 0x02} // 10.1.2.0/24
	addPath := [][2]byte{{1, 1}}
	// Hashes published while path_id was signed, for the update below.
	previous := map[uint32]string{
		1<<31 - 1:  "a42cdb8bba467713cb9fd9ed9dd03538",
		1 << 31:    "a40f51150a52b0997c0d138337d3695f",
		^uint32(0): "8c82837d02956724832cac38632f657b",
	}
	historical := func(action string, id uint32) []byte {
		return []byte(`{"action":"` + action + `","hash":"` + previous[id] +
			`","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"path_id":` +
			strconv.FormatInt(int64(int32(id)), 10) + `}`)
	}
	current := func(t *testing.T, action string, id uint32) []byte {
		t.Helper()
		nlri := testCat(binary.BigEndian.AppendUint32(nil, id), v4Prefix)
		var u *bgp.Update
		if action == "add" {
			u = plainTestUpdate(t, nil, nlri)
		} else {
			u = plainTestUpdate(t, nlri, nil)
		}
		msgs := publishWithPeerUp(t, minimalPeerHeader(), addPath, u)
		if len(msgs) != 1 {
			t.Fatalf("published %d messages, want 1", len(msgs))
		}
		return msgs[0].payload
	}
	apply := func(t *testing.T, store map[string]uint32, event []byte) {
		t.Helper()
		var u UnicastPrefix
		if err := json.Unmarshal(event, &u); err != nil {
			t.Fatalf("%s: %v", event, err)
		}
		switch u.Action {
		case "add":
			store[u.Hash] = u.PathID
		case "del":
			if id, ok := store[u.Hash]; !ok || id != u.PathID {
				t.Errorf("withdrawal %s found %d %v, want path %d", event, id, ok, u.PathID)
			}
			delete(store, u.Hash)
		}
	}
	for id := range previous {
		t.Run(strconv.FormatUint(uint64(id), 10), func(t *testing.T) {
			for _, order := range [][2][]byte{
				{historical("add", id), current(t, "del", id)},
				{current(t, "add", id), historical("del", id)},
			} {
				store := map[string]uint32{}
				apply(t, store, order[0])
				apply(t, store, order[1])
				if len(store) != 0 {
					t.Errorf("store after add then del = %v, want empty", store)
				}
			}
		})
	}
}
