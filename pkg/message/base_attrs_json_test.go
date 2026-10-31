package message

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

// baseAttrsMessageTypes returns a new value of every message type with a
// BaseAttributes field.
func baseAttrsMessageTypes() []baseAttrsHolder {
	return []baseAttrsHolder{
		&UnicastPrefix{}, &L3VPNPrefix{}, &MulticastPrefix{},
		&MCASTVPNPrefix{}, &RTCPrefix{}, &MUPPrefix{}, &EVPNPrefix{}, &VPLSPrefix{},
		&SRPolicy{}, &Flowspec{},
	}
}

// TestBaseAttrsFieldOrder checks every message type encodes base_attrs, from
// the field baseAttrsField returns, after keys of precedesBaseAttrs only and
// before a key it never omits, and is no json.Marshaler, which
// marshalMessage would not splice.
func TestBaseAttrsFieldOrder(t *testing.T) {
	for _, m := range baseAttrsMessageTypes() {
		typ := reflect.TypeOf(m).Elem()
		if _, ok := m.(json.Marshaler); ok {
			t.Errorf("%s is a json.Marshaler", typ)
		}
		if _, ok := m.(encoding.TextMarshaler); ok {
			t.Errorf("%s is an encoding.TextMarshaler", typ)
		}
		seen, after := false, false
		for _, f := range reflect.VisibleFields(typ) {
			tag := f.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" || tag == "-" || !f.IsExported() {
				continue
			}
			switch {
			case name == "base_attrs":
				v := reflect.ValueOf(m).Elem().FieldByIndex(f.Index)
				if tag != "base_attrs,omitempty" || seen || v.Addr().Interface() != any(m.baseAttrsField()) {
					t.Errorf("%s: field %s tagged %q is not the field of baseAttrsField", typ, f.Name, tag)
				}
				seen = true
			case !seen && !precedesBaseAttrs([]byte(name)):
				t.Errorf("%s: %s is encoded before base_attrs", typ, name)
			case seen && precedesBaseAttrs([]byte(name)):
				t.Errorf("%s: %s is encoded after base_attrs", typ, name)
			case seen && !after:
				after = !strings.Contains(opts, "omitempty")
			}
		}
		if !seen || !after {
			t.Errorf("%s: base_attrs found %v, followed by a key never omitted %v", typ, seen, after)
		}
	}
}

// checkSpliced fails unless marshalMessage returns json.Marshal(m) for each of
// msgs in turn, with the cache on.
func checkSpliced(t *testing.T, msgs ...any) {
	t.Helper()
	c := baseAttrsCache{on: true}
	for i, m := range msgs {
		want, wantErr := json.Marshal(m)
		got, err := marshalMessage(m, &c)
		if (err != nil) != (wantErr != nil) || !bytes.Equal(got, want) {
			t.Fatalf("%T route %d: marshalMessage() = %s, %v\nwant %s, %v", m, i, got, err, want, wantErr)
		}
	}
}

// TestMarshalMessage checks the JSON of routes sharing base_attrs, passed as
// the producer does, by pointer and by pointer to pointer, is as json.Marshal
// writes it, through changes of the attributes, as the next UPDATE brings.
func TestMarshalMessage(t *testing.T) {
	shared := &bgp.BaseAttributes{Origin: "igp", CommunityList: []string{"a\"<&>\\ é"}, AS4Aggregator: []byte{0xff}}
	next := &bgp.BaseAttributes{}
	for _, proto := range baseAttrsMessageTypes() {
		var byPtr, byPtrPtr []any
		for _, attrs := range []*bgp.BaseAttributes{shared, shared, next, next, nil, shared} {
			v := reflect.New(reflect.TypeOf(proto).Elem())
			*v.Interface().(baseAttrsHolder).baseAttrsField() = attrs
			pp := reflect.New(v.Type())
			pp.Elem().Set(v)
			byPtr, byPtrPtr = append(byPtr, v.Interface()), append(byPtrPtr, pp.Interface())
		}
		checkSpliced(t, byPtr...)
		checkSpliced(t, byPtrPtr...)
	}
	// Values that look like the key, or hold its closing brace, are skipped as
	// strings.
	var routes []any
	for _, s := range []string{`"base_attrs":{}`, `}"`, `\`} {
		routes = append(routes, &UnicastPrefix{BaseAttributes: shared, RouterIP: s, Hash: s})
	}
	checkSpliced(t, routes...)
	// A first route whose JSON has no base_attrs key falls back to json.Marshal.
	checkSpliced(t, &hiddenHolder{shared}, &hiddenHolder{shared})
}

// hiddenHolder is a message type that never encodes its BaseAttributes.
type hiddenHolder struct {
	BaseAttributes *bgp.BaseAttributes `json:"-"`
}

func (m *hiddenHolder) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }

// marshalerHolder is a message type that encodes itself.
type marshalerHolder struct {
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
}

func (m *marshalerHolder) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }
func (m *marshalerHolder) MarshalJSON() ([]byte, error)         { return []byte(`{"own":1}`), nil }

// panicHolder is a message type whose encoding fails, or panics, when it is
// set to.
type panicHolder struct {
	Router         string              `json:"router_ip"`
	BaseAttributes *bgp.BaseAttributes `json:"base_attrs,omitempty"`
	Panic          panicValue          `json:"p"`
}

type panicValue int

const (
	encodeOK panicValue = iota
	encodeError
	encodePanic
)

func (p panicValue) MarshalJSON() ([]byte, error) {
	switch p {
	case encodeError:
		return nil, errors.New("encode")
	case encodePanic:
		panic("panicValue")
	}
	return []byte("0"), nil
}

func (m *panicHolder) baseAttrsField() **bgp.BaseAttributes { return &m.BaseAttributes }

// TestMarshalMessageRefusesAndRestores checks marshalMessage does not splice
// a json.Marshaler, nor while off, and restores the BaseAttributes of a
// message whose encoding panics.
func TestMarshalMessageRefusesAndRestores(t *testing.T) {
	attrs := &bgp.BaseAttributes{Origin: "igp"}
	c := baseAttrsCache{on: true}
	for i := 0; i < 2; i++ {
		if got, _ := marshalMessage(&marshalerHolder{BaseAttributes: attrs}, &c); string(got) != `{"own":1}` || c.attrs != nil {
			t.Fatalf("json.Marshaler: got %s, cache %+v", got, c)
		}
	}
	var off baseAttrsCache
	for i := 0; i < 2; i++ {
		_, _ = marshalMessage(&UnicastPrefix{BaseAttributes: attrs}, &off)
	}
	if off.attrs != nil {
		t.Fatalf("cache used while off: %+v", off)
	}
	m := &panicHolder{BaseAttributes: attrs}
	if _, err := marshalMessage(m, &c); err != nil {
		t.Fatal(err)
	}
	// An error, as the second route of an UPDATE, is returned.
	m.Panic = encodeError
	if _, err := marshalMessage(m, &c); err == nil {
		t.Fatal("encoding error not returned")
	}
	m.Panic = encodePanic
	func() {
		defer func() { _ = recover() }()
		_, _ = marshalMessage(m, &c)
	}()
	if m.BaseAttributes != attrs {
		t.Fatalf("BaseAttributes not restored after a panic: %v", m.BaseAttributes)
	}
}

// TestBaseAttrsAt checks baseAttrsAt on objects encoding/json does and does
// not write.
func TestBaseAttrsAt(t *testing.T) {
	for j, want := range map[string]int{
		``: -1, `[]`: -1, `{`: -1, `{"hash"`: -1, `{"hash":`: -1, `{"hash":"x`: -1, `{"hash":1`: -1,
		`{}`: 1, `{"x":1}`: 1, `{"hash":1}`: 9, `{"hash":"a\"}","x":2}`: 15, `{"_key":"k","hash":{"a":[1,"}"]},"x":2}`: 33,
	} {
		if got := baseAttrsAt([]byte(j)); got != want {
			t.Errorf("baseAttrsAt(%q) = %d, want %d", j, got, want)
		}
	}
}
