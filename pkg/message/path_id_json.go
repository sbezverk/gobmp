package message

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// pathIDJSON reads an RFC 7911 Path Identifier (a four-octet field, Section
// 3) published either unsigned or, before path_id became uint32, as its
// signed 32-bit reading, so -1 and 4294967295 decode to the same ID.
type pathIDJSON uint32

func (p *pathIDJSON) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	v, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil || v < math.MinInt32 || v > math.MaxUint32 {
		return fmt.Errorf("path_id %s is not a 32-bit Path Identifier", b)
	}
	*p = pathIDJSON(uint32(v))
	return nil
}

// UnmarshalJSON accepts the historical signed path_id as well as the unsigned one.
func (u *UnicastPrefix) UnmarshalJSON(b []byte) error {
	type fields UnicastPrefix
	aux := struct {
		*fields
		PathID pathIDJSON `json:"path_id"`
	}{fields: (*fields)(u), PathID: pathIDJSON(u.PathID)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	u.PathID = uint32(aux.PathID)
	return nil
}

// UnmarshalJSON accepts the historical signed path_id as well as the unsigned one.
func (m *MulticastPrefix) UnmarshalJSON(b []byte) error {
	type fields MulticastPrefix
	aux := struct {
		*fields
		PathID pathIDJSON `json:"path_id"`
	}{fields: (*fields)(m), PathID: pathIDJSON(m.PathID)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	m.PathID = uint32(aux.PathID)
	return nil
}

// UnmarshalJSON accepts the historical signed path_id as well as the unsigned one.
func (m *MUPPrefix) UnmarshalJSON(b []byte) error {
	type fields MUPPrefix
	aux := struct {
		*fields
		PathID pathIDJSON `json:"path_id"`
	}{fields: (*fields)(m), PathID: pathIDJSON(m.PathID)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	m.PathID = uint32(aux.PathID)
	return nil
}

// UnmarshalJSON accepts the historical signed path_id as well as the unsigned one.
func (l *L3VPNPrefix) UnmarshalJSON(b []byte) error {
	type fields L3VPNPrefix
	aux := struct {
		*fields
		PathID pathIDJSON `json:"path_id"`
	}{fields: (*fields)(l), PathID: pathIDJSON(l.PathID)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	l.PathID = uint32(aux.PathID)
	return nil
}
