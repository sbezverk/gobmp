package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// TerminationMessage defines BMP Termination Message per RFC 7854 §4.5.
// HasReason is false when no Reason TLV is present (RFC 7854 says it is REQUIRED,
// but a defensive implementation should not crash on a malformed/incomplete message).
type TerminationMessage struct {
	HasReason bool
	Reason    uint16
	Strings   []string
}

// ReasonString returns a human-readable description of the termination reason.
func (t *TerminationMessage) ReasonString() string {
	if !t.HasReason {
		return "no reason TLV present"
	}
	switch t.Reason {
	case TermReasonAdminClosed:
		return "administratively closed (may re-initiate)"
	case TermReasonUnspecified:
		return "unspecified reason"
	case TermReasonOutOfResources:
		return "out of resources"
	case TermReasonRedundant:
		return "redundant connection"
	case TermReasonPermAdminClosed:
		return "permanently administratively closed"
	default:
		return fmt.Sprintf("unknown reason code %d", t.Reason)
	}
}

// UnmarshalTerminationMessage processes the body of a BMP Termination Message.
// The common header must be stripped before passing b to this function.
// The body consists of one or more TLVs: type 0 (String) and type 1 (Reason code).
// Unknown TLV types are silently skipped per RFC 7854 extensibility rules.
func UnmarshalTerminationMessage(b []byte) (*TerminationMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Termination Message Raw: %s", tools.MessageHex(b))
	}
	tm := &TerminationMessage{}
	tlvs, err := UnmarshalTLV(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Termination Message TLVs: %w", err)
	}
	for _, tlv := range tlvs {
		switch tlv.InformationType {
		case 0: // String TLV — optional human-readable detail
			tm.Strings = append(tm.Strings, string(tlv.Information))
		case 1: // Reason TLV — 2-byte reason code
			if len(tlv.Information) < 2 {
				return nil, fmt.Errorf("termination reason TLV too short: %d bytes", len(tlv.Information))
			}
			tm.Reason = binary.BigEndian.Uint16(tlv.Information[:2])
			tm.HasReason = true
			// Unknown TLV types are silently ignored
		}
	}
	return tm, nil
}
