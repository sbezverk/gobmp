package message

import (
	"bytes"
	"encoding"
	"encoding/json"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// The routes of an UPDATE share its path attributes, so their JSON is mostly
// one base_attrs value. While a Route Monitoring message is produced,
// marshalMessage takes that value out of the JSON of the first route and
// splices it into the JSON of the next ones, encoded without BaseAttributes.

// baseAttrsHolder is a message with a BaseAttributes field. Every such type
// encodes it as base_attrs after keys of precedesBaseAttrs only, and before
// a key it never omits.
type baseAttrsHolder interface {
	baseAttrsField() **bgp.BaseAttributes
}

func (m *UnicastPrefix) baseAttrsField() **bgp.BaseAttributes   { return &m.BaseAttributes }
func (m *L3VPNPrefix) baseAttrsField() **bgp.BaseAttributes     { return &m.BaseAttributes }
func (m *MulticastPrefix) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }
func (m *MCASTVPNPrefix) baseAttrsField() **bgp.BaseAttributes  { return &m.BaseAttributes }
func (m *RTCPrefix) baseAttrsField() **bgp.BaseAttributes       { return &m.BaseAttributes }
func (m *MUPPrefix) baseAttrsField() **bgp.BaseAttributes       { return &m.BaseAttributes }
func (m *EVPNPrefix) baseAttrsField() **bgp.BaseAttributes      { return &m.BaseAttributes }
func (m *VPLSPrefix) baseAttrsField() **bgp.BaseAttributes      { return &m.BaseAttributes }
func (m *SRPolicy) baseAttrsField() **bgp.BaseAttributes        { return &m.BaseAttributes }
func (m *Flowspec) baseAttrsField() **bgp.BaseAttributes        { return &m.BaseAttributes }

func precedesBaseAttrs(key []byte) bool {
	switch string(key) {
	case "_key", "_id", "_rev", "action", "sequence", "hash", "router_hash", "router_ip":
		return true
	}
	return false
}

// baseAttrsCache is on while a Route Monitoring message is produced. It
// holds the BaseAttributes of the last route, the JSON of the first route
// with them and, from the second, its base_attrs value. The producer copies
// the attributes for each MP_REACH_NLRI, MP_UNREACH_NLRI and NLRI field and
// changes a copy only before it builds its routes, so meanwhile a pointer
// stands for one encoding. Publishers do not modify what they are given.
//
// scratch is reused to encode routes and is never returned: what marshalMessage
// returns is a fresh slice, which publishers may keep. A cache belongs to one
// producer, which handles one message at a time.
type baseAttrsCache struct {
	on           bool
	attrs        *bgp.BaseAttributes
	first, value []byte
	scratch      bytes.Buffer
}

var baseAttrsKey = []byte(`"base_attrs":`)

// marshalMessage returns json.Marshal(msg), splicing in the base_attrs of c
// when msg has the BaseAttributes of the last route.
func marshalMessage(msg any, c *baseAttrsCache) ([]byte, error) {
	var h baseAttrsHolder
	switch m := msg.(type) {
	case baseAttrsHolder:
		h = m
	case **UnicastPrefix:
		h = *m
	case **MulticastPrefix:
		h = *m
	case **MCASTVPNPrefix:
		h = *m
	case **RTCPrefix:
		h = *m
	case **SRPolicy:
		h = *m
	case **Flowspec:
		h = *m
	}
	_, marshaler := h.(json.Marshaler)
	_, textMarshaler := h.(encoding.TextMarshaler)
	if !c.on || h == nil || marshaler || textMarshaler || *h.baseAttrsField() == nil {
		return json.Marshal(msg)
	}
	field := h.baseAttrsField()
	if *field != c.attrs {
		j, err := json.Marshal(msg)
		c.attrs, c.first, c.value = nil, nil, nil
		if err == nil {
			c.attrs, c.first = *field, j
		}
		return j, err
	}
	if c.value == nil {
		at, end := baseAttrsAt(c.first), -1
		if at >= 0 && bytes.HasPrefix(c.first[at:], baseAttrsKey) {
			end = skipValue(c.first, at+len(baseAttrsKey))
		}
		if end < 0 {
			c.attrs = nil
			return json.Marshal(msg)
		}
		c.value = c.first[at+len(baseAttrsKey) : end]
	}
	j, err := marshalWithout(msg, field, &c.scratch)
	at := -1
	if err == nil {
		at = baseAttrsAt(j)
	}
	if at < 0 || j[at] != '"' {
		return json.Marshal(msg)
	}
	out := make([]byte, 0, len(j)+len(baseAttrsKey)+len(c.value)+1)
	out = append(append(append(out, j[:at]...), baseAttrsKey...), c.value...)
	return append(append(out, ','), j[at:]...), nil
}

// marshalWithout returns json.Marshal(msg) with its BaseAttributes field
// nil, and restores it, even on a panic. The result is in buf and valid only
// until the next call: the caller copies what it publishes out of it.
func marshalWithout(msg any, field **bgp.BaseAttributes, buf *bytes.Buffer) ([]byte, error) {
	attrs := *field
	*field = nil
	defer func() { *field = attrs }()
	buf.Reset()
	// Encode escapes HTML like Marshal does; it only adds a newline.
	if err := json.NewEncoder(buf).Encode(msg); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// start turns the cache on for one Route Monitoring message, keeping the
// scratch buffer.
func (c *baseAttrsCache) start() {
	*c = baseAttrsCache{on: true, scratch: c.scratch}
}

// stop turns the cache off and drops the encodings it holds.
func (c *baseAttrsCache) stop() {
	*c = baseAttrsCache{scratch: c.scratch}
}

// baseAttrsAt returns the offset in j, an object as encoding/json writes it,
// of the first member whose key is not one of precedesBaseAttrs, or else of
// the closing brace; -1 if j is not such an object.
func baseAttrsAt(j []byte) int {
	for i := 1; len(j) > 1 && j[0] == '{' && i < len(j); i++ {
		if j[i] == '}' {
			return i
		}
		end := skipValue(j, i) // the key
		if j[i] != '"' || end < 0 || end >= len(j) || j[end] != ':' {
			return -1
		}
		if !precedesBaseAttrs(j[i+1 : end-1]) {
			return i
		}
		if i = skipValue(j, end+1); i < 0 || i >= len(j) || j[i] != ',' {
			return i
		}
	}
	return -1
}

// skipValue returns the offset after the JSON value, or key, at j[i]; -1 if
// j ends before.
func skipValue(j []byte, i int) int {
	depth := 0
	for ; i < len(j); i++ {
		switch j[i] {
		case '"':
			for i++; i < len(j) && j[i] != '"'; i++ {
				if j[i] == '\\' {
					i++
				}
			}
			if depth == 0 && i < len(j) {
				return i + 1
			}
		case '{', '[':
			depth++
		case '}', ']', ',':
			if depth == 0 {
				return i
			}
			if j[i] != ',' {
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
	}
	return -1
}
