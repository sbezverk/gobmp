package nats

import (
	"errors"
	"strings"
	"testing"

	natsgo "github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// fakeJetStream is a minimal jetStreamClient used in unit tests.
type fakeJetStream struct {
	addStreamFn    func(*natsgo.StreamConfig, ...natsgo.JSOpt) (*natsgo.StreamInfo, error)
	streamInfoFn   func(string, ...natsgo.JSOpt) (*natsgo.StreamInfo, error)
	updateStreamFn func(*natsgo.StreamConfig, ...natsgo.JSOpt) (*natsgo.StreamInfo, error)
}

func (f *fakeJetStream) PublishMsg(m *natsgo.Msg, _ ...natsgo.PubOpt) (*natsgo.PubAck, error) {
	return nil, nil
}
func (f *fakeJetStream) AddStream(cfg *natsgo.StreamConfig, opts ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
	return f.addStreamFn(cfg, opts...)
}
func (f *fakeJetStream) StreamInfo(stream string, opts ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
	return f.streamInfoFn(stream, opts...)
}
func (f *fakeJetStream) UpdateStream(cfg *natsgo.StreamConfig, opts ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
	return f.updateStreamFn(cfg, opts...)
}

func TestTopicForMessage(t *testing.T) {
	tests := []struct {
		msgType   int
		wantTopic string
		wantOK    bool
	}{
		{bmp.PeerStateChangeMsg, peerTopic, true},
		{bmp.UnicastPrefixMsg, unicastMessageTopic, true},
		{bmp.UnicastPrefixV4Msg, unicastMessageV4Topic, true},
		{bmp.UnicastPrefixV6Msg, unicastMessageV6Topic, true},
		{bmp.LSNodeMsg, lsNodeMessageTopic, true},
		{bmp.LSLinkMsg, lsLinkMessageTopic, true},
		{bmp.L3VPNMsg, l3vpnMessageTopic, true},
		{bmp.L3VPNV4Msg, l3vpnMessageV4Topic, true},
		{bmp.L3VPNV6Msg, l3vpnMessageV6Topic, true},
		{bmp.LSPrefixMsg, lsPrefixMessageTopic, true},
		{bmp.LSSRv6SIDMsg, lsSRv6SIDMessageTopic, true},
		{bmp.EVPNMsg, evpnMessageTopic, true},
		{bmp.SRPolicyMsg, srPolicyMessageTopic, true},
		{bmp.SRPolicyV4Msg, srPolicyMessageV4Topic, true},
		{bmp.SRPolicyV6Msg, srPolicyMessageV6Topic, true},
		{bmp.FlowspecMsg, flowspecMessageTopic, true},
		{bmp.FlowspecV4Msg, flowspecMessageV4Topic, true},
		{bmp.FlowspecV6Msg, flowspecMessageV6Topic, true},
		{bmp.VPLSMsg, vplsMessageTopic, true},
		{bmp.StatsReportMsg, statsMessageTopic, true},
		{bmp.BMPRawMsg, rawMessageTopic, true},
		{9999, "", false},
	}

	for _, tt := range tests {
		topic, ok := topicForMessage(tt.msgType)
		if ok != tt.wantOK {
			t.Errorf("topicForMessage(%d): ok=%v, want %v", tt.msgType, ok, tt.wantOK)
			continue
		}
		if topic != tt.wantTopic {
			t.Errorf("topicForMessage(%d): topic=%q, want %q", tt.msgType, topic, tt.wantTopic)
		}
	}
}

func TestMergeSubjects(t *testing.T) {
	tests := []struct {
		name        string
		existing    []string
		required    []string
		wantOut     []string
		wantChanged bool
	}{
		{
			name:        "all already present — no update",
			existing:    []string{"a", "b"},
			required:    []string{"a", "b"},
			wantOut:     []string{"a", "b"},
			wantChanged: false,
		},
		{
			name:        "one missing — update",
			existing:    []string{"a"},
			required:    []string{"a", "b"},
			wantOut:     []string{"a", "b"},
			wantChanged: true,
		},
		{
			name:        "empty existing — all added",
			existing:    []string{},
			required:    []string{"a", "b"},
			wantOut:     []string{"a", "b"},
			wantChanged: true,
		},
		{
			name:        "empty required — no change",
			existing:    []string{"a"},
			required:    []string{},
			wantOut:     []string{"a"},
			wantChanged: false,
		},
		{
			name:        "existing not modified",
			existing:    []string{"x"},
			required:    []string{"y"},
			wantOut:     []string{"x", "y"},
			wantChanged: true,
		},
		{
			name:        "duplicate entries in required — deduplicated in output",
			existing:    []string{},
			required:    []string{"a", "a", "b"},
			wantOut:     []string{"a", "b"},
			wantChanged: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origLen := len(tt.existing)
			got, changed := mergeSubjects(tt.existing, tt.required)
			if changed != tt.wantChanged {
				t.Errorf("changed=%v, want %v", changed, tt.wantChanged)
			}
			if len(got) != len(tt.wantOut) {
				t.Fatalf("len(got)=%d, want %d: %v", len(got), len(tt.wantOut), got)
			}
			for i, s := range tt.wantOut {
				if got[i] != s {
					t.Errorf("got[%d]=%q, want %q", i, got[i], s)
				}
			}
			if len(tt.existing) != origLen {
				t.Errorf("mergeSubjects modified existing slice (len %d → %d)", origLen, len(tt.existing))
			}
		})
	}
}

func TestCreateStreams(t *testing.T) {
	errBoom := errors.New("boom")
	errStreamInfoFail := errors.New("stream info failed")
	errUpdateFail := errors.New("update failed")

	tests := []struct {
		name           string
		addStreamErr   error
		existingSubjs  []string
		streamInfoErr  error
		updateStreamFn func(*natsgo.StreamConfig, ...natsgo.JSOpt) (*natsgo.StreamInfo, error)
		wantErr        bool
		wantErrContain string
	}{
		{
			name:         "new stream created successfully",
			addStreamErr: nil,
			wantErr:      false,
		},
		{
			name:           "add stream non-alreadyInUse error",
			addStreamErr:   errBoom,
			wantErr:        true,
			wantErrContain: "failed to create stream",
		},
		{
			name:           "already exists — StreamInfo error",
			addStreamErr:   natsgo.ErrStreamNameAlreadyInUse,
			streamInfoErr:  errStreamInfoFail,
			wantErr:        true,
			wantErrContain: "failed to get stream info",
		},
		{
			name:          "already exists — all subjects present — no update",
			addStreamErr:  natsgo.ErrStreamNameAlreadyInUse,
			existingSubjs: []string{parsedWildcardSubject, rawMessageTopic},
			wantErr:       false,
		},
		{
			name:          "already exists — missing raw subject — update succeeds",
			addStreamErr:  natsgo.ErrStreamNameAlreadyInUse,
			existingSubjs: []string{parsedWildcardSubject},
			updateStreamFn: func(cfg *natsgo.StreamConfig, _ ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
				return &natsgo.StreamInfo{Config: *cfg}, nil
			},
			wantErr: false,
		},
		{
			name:          "already exists — missing raw subject — update fails",
			addStreamErr:  natsgo.ErrStreamNameAlreadyInUse,
			existingSubjs: []string{parsedWildcardSubject},
			updateStreamFn: func(_ *natsgo.StreamConfig, _ ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
				return nil, errUpdateFail
			},
			wantErr:        true,
			wantErrContain: "failed to update stream subjects",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeJetStream{
				addStreamFn: func(_ *natsgo.StreamConfig, _ ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
					return nil, tt.addStreamErr
				},
				streamInfoFn: func(_ string, _ ...natsgo.JSOpt) (*natsgo.StreamInfo, error) {
					if tt.streamInfoErr != nil {
						return nil, tt.streamInfoErr
					}
					return &natsgo.StreamInfo{
						Config: natsgo.StreamConfig{Subjects: tt.existingSubjs},
					}, nil
				},
				updateStreamFn: tt.updateStreamFn,
			}
			p := &publisher{js: fake}
			err := p.createStreams()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.wantErrContain != "" && !strings.Contains(err.Error(), tt.wantErrContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRawTopicNotUnderParsedWildcard(t *testing.T) {
	// gobmp.raw must remain the exact subject for raw messages — the
	// gobmp.parsed.* wildcard only matches three-segment subjects, so
	// gobmp.raw has to be added to the stream Subjects explicitly. Lock
	// the literal value so a rename to gobmp.parsed.raw, gobmp.raw.v2, or
	// anything else is caught and Kafka parity is preserved.
	const wantRawTopic = "gobmp.raw"
	if rawMessageTopic != wantRawTopic {
		t.Errorf("rawMessageTopic=%q, want exactly %q (rename would break Kafka parity)", rawMessageTopic, wantRawTopic)
	}
	topic, ok := topicForMessage(bmp.BMPRawMsg)
	if !ok || topic != wantRawTopic {
		t.Errorf("BMPRawMsg must map to %q, got %q ok=%v", wantRawTopic, topic, ok)
	}
}
