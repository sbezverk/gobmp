package main

import "encoding/json"

const injectPath = "/v1/routes"

type Fixture struct {
	SchemaVersion int         `json:"schema_version"`
	Name          string      `json:"name"`
	Description   string      `json:"description,omitempty"`
	Tags          []string    `json:"tags,omitempty"`
	Inject        HTTPAction  `json:"inject"`
	Observe       ObserveSpec `json:"observe"`
	Expect        ExpectSpec  `json:"expect"`
	Cleanup       *HTTPAction `json:"cleanup,omitempty"`
}

type HTTPAction struct {
	Path string          `json:"path"`
	Body json.RawMessage `json:"body"`
}

type ObserveSpec struct {
	Source     string         `json:"source"`
	Topic      string         `json:"topic"`
	Timeout    string         `json:"timeout"`
	timeoutSec int            `json:"-"`
	Match      map[string]any `json:"match,omitempty"`
}

type ExpectSpec struct {
	Equals   map[string]any `json:"equals,omitempty"`
	Contains map[string]any `json:"contains,omitempty"`
	Present  []string       `json:"present,omitempty"`
	Absent   []string       `json:"absent,omitempty"`
}

type SessionResponse struct {
	State              string   `json:"state"`
	LastError          string   `json:"last_error,omitempty"`
	SpeakerAddress     string   `json:"speaker_address"`
	LocalAS            uint32   `json:"local_as"`
	RouterID           string   `json:"router_id"`
	RemoteAS           uint32   `json:"remote_as,omitempty"`
	RemoteID           string   `json:"remote_id,omitempty"`
	FourByteAS         bool     `json:"four_byte_as"`
	NextHopMode        string   `json:"next_hop_mode"`
	RewriteNextHop     string   `json:"rewrite_next_hop,omitempty"`
	RewriteNextHopV6   string   `json:"rewrite_next_hop_v6,omitempty"`
	HoldTime           uint16   `json:"hold_time,omitempty"`
	EstablishedAt      string   `json:"established_at,omitempty"`
	UptimeSeconds      int64    `json:"uptime_seconds,omitempty"`
	SentUpdates        uint64   `json:"sent_updates"`
	ReceivedMessages   uint64   `json:"received_messages"`
	NegotiatedFamilies []string `json:"negotiated_families,omitempty"`
}

type InjectResponse struct {
	Accepted int            `json:"accepted"`
	Updates  []InjectUpdate `json:"updates"`
}

type InjectUpdate struct {
	Prefix string `json:"prefix"`
	Action string `json:"action"`
	Queued bool   `json:"queued,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

type APIErrorResponse struct {
	Error string `json:"error"`
}
