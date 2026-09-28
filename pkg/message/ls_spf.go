package message

import (
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/ls"
)

const (
	bgpLSSPFSequenceNumberTLV   = 1181
	bgpLSSPFStatusTLV           = 1184
	bgpLSSPFAFLinkDescriptorTLV = 1185
	bgpLSIGPMetricTLV           = 1095
	bgpLSPrefixMetricTLV        = 1155
)

type nlri80 interface {
	GetNLRI80() (*ls.NLRI71, error)
}

type nlri71View struct {
	bgp.MPNLRI
	nlri *ls.NLRI71
}

func (n nlri71View) GetNLRI71() (*ls.NLRI71, error) {
	return n.nlri, nil
}

// processNLRI80SubTypes handles BGP-LS-SPF (AFI 16388 / SAFI 80) updates.
// Per RFC 9815 Sections 5.1 and 5.2, its NLRI wire encoding is BGP-LS with
// additional receiver-side validation before existing BGP-LS publication.
func (p *producer) processNLRI80SubTypes(nlri bgp.MPNLRI, operation int, ph *bmp.PerPeerHeader, update *bgp.Update) {
	// The lsNode/lsLink/lsPrefix handlers dereference update on every
	// path, including the treat-as-withdraw path below.
	if update == nil {
		glog.Errorf("bgp-ls-spf update is nil")
		return
	}
	spfNLRI, ok := nlri.(nlri80)
	if !ok {
		glog.Errorf("bgp-ls-spf NLRI does not implement GetNLRI80")
		return
	}
	parsed, err := spfNLRI.GetNLRI80()
	if err != nil {
		glog.Errorf("failed to decode bgp-ls-spf NLRI: %+v", err)
		return
	}
	if operation != AddPrefix {
		p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: parsed}, operation, ph, update, true)
		return
	}
	valid, invalid, err := splitLSNLRI80(parsed, update)
	if err != nil {
		glog.Errorf("invalid bgp-ls-spf NLRI: %+v", err)
		// Per RFC 9815 Section 7.1, malformed NLRIs are treated as withdrawn.
		p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: parsed}, DelPrefix, ph, update, true)
		return
	}
	if len(invalid.NLRI) > 0 {
		// Per RFC 9815 Section 7.1, elements that fail validation are
		// treated as withdrawn without discarding the elements that pass.
		p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: invalid}, DelPrefix, ph, update, true)
	}
	if len(valid.NLRI) > 0 {
		p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: valid}, operation, ph, update, true)
	}
}

// splitLSNLRI80 validates a BGP-LS-SPF NLRI per RFC 9815 Section 5.2 and
// splits its Elements into ones that pass validation and ones that must be
// withdrawn. A non-nil error means the BGP-LS Attribute itself — shared by
// every Element — failed validation, so the entire NLRI must be withdrawn.
func splitLSNLRI80(nlri *ls.NLRI71, update *bgp.Update) (valid, invalid *ls.NLRI71, err error) {
	if nlri == nil {
		return nil, nil, fmt.Errorf("bgp-ls-spf NLRI is nil")
	}
	if update == nil {
		return nil, nil, fmt.Errorf("bgp-ls-spf update is nil")
	}
	attribute, err := update.GetBGPLSAttribute()
	if err != nil {
		var missing *bgp.AttributeNotFoundError
		if errors.As(err, &missing) {
			// RFC 9815 Section 7.1 retains NLRIs after BGP-LS Attribute
			// discard, although a BGP speaker must not use them for SPF.
			empty := *nlri
			empty.NLRI = nil
			return nlri, &empty, nil
		}
		return nil, nil, fmt.Errorf("invalid bgp-ls attribute: %w", err)
	}
	if err := validateLSNLRI80Attribute(attribute); err != nil {
		return nil, nil, err
	}
	if err := validateLSNLRI80Status(attribute); err != nil {
		return nil, nil, err
	}

	validElements := *nlri
	validElements.NLRI = nil
	invalidElements := *nlri
	invalidElements.NLRI = nil
	for _, element := range nlri.NLRI {
		if err := validateLSNLRI80Element(element, attribute); err != nil {
			glog.Errorf("invalid bgp-ls-spf NLRI element: %+v", err)
			invalidElements.NLRI = append(invalidElements.NLRI, element)
			continue
		}
		validElements.NLRI = append(validElements.NLRI, element)
	}
	return &validElements, &invalidElements, nil
}

// validateLSNLRI80Element validates one Element's descriptor and mandatory
// metric TLV per RFC 9815 Section 5.2.1 (Node/Link/Prefix constraints).
// Other Element types pass through unchanged: RFC 9552 Section 5.2, "An
// implementation MUST handle unknown Link-State NLRI types as opaque objects
// and MUST preserve and propagate them."
func validateLSNLRI80Element(element ls.Element, attribute *bgpls.NLRI) error {
	switch element.Type {
	case 1:
		node, ok := element.LS.(*base.NodeNLRI)
		if !ok {
			return fmt.Errorf("bgp-ls-spf node NLRI has unexpected type %T", element.LS)
		}
		if node.ProtocolID != base.Direct {
			return fmt.Errorf("bgp-ls-spf node NLRI has protocol ID %d, want %d", node.ProtocolID, base.Direct)
		}
		return validateLSNLRI80NodeDescriptor(node.LocalNode)
	case 2:
		link, ok := element.LS.(*base.LinkNLRI)
		if !ok {
			return fmt.Errorf("bgp-ls-spf link NLRI has unexpected type %T", element.LS)
		}
		if link.ProtocolID != base.Direct {
			return fmt.Errorf("bgp-ls-spf link NLRI has protocol ID %d, want %d", link.ProtocolID, base.Direct)
		}
		if err := validateLSNLRI80NodeDescriptor(link.LocalNode); err != nil {
			return fmt.Errorf("bgp-ls-spf link local node descriptor: %w", err)
		}
		if err := validateLSNLRI80NodeDescriptor(link.RemoteNode); err != nil {
			return fmt.Errorf("bgp-ls-spf link remote node descriptor: %w", err)
		}
		if err := validateLSNLRI80AFLinkDescriptor(link.Link); err != nil {
			return err
		}
		return validateLSNLRI80Metric(bgpLSIGPMetricTLV, attribute, true)
	case 3, 4:
		// Per RFC 9815 Section 5.2, the Prefix NLRI Protocol-ID is the
		// prefix origin, so Direct is not required.
		prefix, ok := element.LS.(*base.PrefixNLRI)
		if !ok {
			return fmt.Errorf("bgp-ls-spf prefix NLRI has unexpected type %T", element.LS)
		}
		if err := validateLSNLRI80NodeDescriptor(prefix.LocalNode); err != nil {
			return err
		}
		return validateLSNLRI80Metric(bgpLSPrefixMetricTLV, attribute, false)
	default:
		return nil
	}
}

// validateLSNLRI80NodeDescriptor checks the length of the Autonomous System
// (512) and BGP Router-ID (516) sub-TLVs that RFC 9815 Section 5.2 requires.
// An absent one is not malformed: per RFC 9815 Section 5.1.1, "If a mandatory
// TLV is not present, the NLRI MUST NOT be used in the BGP SPF route
// calculation", which is the SPF speaker's decision, not a withdrawal.
func validateLSNLRI80NodeDescriptor(descriptor *base.NodeDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("missing node descriptor")
	}
	for _, typeAndLength := range []struct {
		typeID uint16
		length uint16
	}{
		{typeID: 512, length: 4},
		{typeID: 516, length: 4},
	} {
		tlv, ok := descriptor.SubTLV[typeAndLength.typeID]
		if !ok {
			continue
		}
		if tlv.Length != typeAndLength.length || len(tlv.Value) != int(typeAndLength.length) {
			return fmt.Errorf("node descriptor TLV %d has length %d, want %d", typeAndLength.typeID, tlv.Length, typeAndLength.length)
		}
	}
	return nil
}

// validateLSNLRI80Attribute checks that the BGP-LS Attribute carries exactly
// one well-formed SPF Sequence Number TLV (1181) per RFC 9815 Section 5.2.4.
func validateLSNLRI80Attribute(attribute *bgpls.NLRI) error {
	sequenceNumbers := 0
	for _, tlv := range attribute.LS {
		if tlv.Type != bgpLSSPFSequenceNumberTLV {
			continue
		}
		if tlv.Length != 8 || len(tlv.Value) != 8 {
			return fmt.Errorf("bgp-ls-spf sequence number TLV has length %d, want 8", tlv.Length)
		}
		sequenceNumbers++
	}
	if sequenceNumbers != 1 {
		return fmt.Errorf("bgp-ls-spf attribute has %d sequence number TLVs, want 1", sequenceNumbers)
	}
	return nil
}

// validateLSNLRI80Metric checks that every metric TLV of the given type is
// four octets. Per RFC 9815 Section 5.2.2 a Link NLRI without IGP Metric
// (1095) is malformed (required=true); per Section 5.2.3 a Prefix NLRI
// without Prefix Metric (1155) is only excluded from SPF, not malformed.
func validateLSNLRI80Metric(metricType uint16, attribute *bgpls.NLRI, required bool) error {
	found := false
	for _, tlv := range attribute.LS {
		if tlv.Type != metricType {
			continue
		}
		found = true
		if tlv.Length != 4 || len(tlv.Value) != 4 {
			return fmt.Errorf("bgp-ls-spf metric TLV %d has length %d, want 4", metricType, tlv.Length)
		}
	}
	if required && !found {
		return fmt.Errorf("bgp-ls-spf NLRI requires metric TLV %d", metricType)
	}
	return nil
}

// validateLSNLRI80Status checks every SPF Status TLV (1184) present in the
// BGP-LS Attribute is one octet and not a reserved value (0 or 255). Per
// RFC 9815 Sections 5.2.1.1, 5.2.2.2 and 5.2.3.1 the TLV is optional: when
// absent the object is up/reachable, so absence is not an error.
func validateLSNLRI80Status(attribute *bgpls.NLRI) error {
	for _, tlv := range attribute.LS {
		if tlv.Type != bgpLSSPFStatusTLV {
			continue
		}
		if tlv.Length != 1 || len(tlv.Value) != 1 {
			return fmt.Errorf("bgp-ls-spf status TLV has length %d, want 1", tlv.Length)
		}
		if tlv.Value[0] == 0 || tlv.Value[0] == 255 {
			return fmt.Errorf("bgp-ls-spf status TLV has reserved value %d", tlv.Value[0])
		}
	}
	return nil
}

// validateLSNLRI80AFLinkDescriptor checks an optional Address Family Link
// Descriptor TLV (1185) is one octet and not a reserved value (0 or 255).
// Per RFC 9815 Sections 5.2.2.1 and 7.1 a malformed TLV makes the Link NLRI
// malformed; undefined values (3-254) are ignored, not rejected.
func validateLSNLRI80AFLinkDescriptor(link *base.LinkDescriptor) error {
	if link == nil {
		return nil
	}
	tlv, ok := link.LinkTLV[bgpLSSPFAFLinkDescriptorTLV]
	if !ok {
		return nil
	}
	if tlv.Length != 1 || len(tlv.Value) != 1 {
		return fmt.Errorf("bgp-ls-spf address family link descriptor TLV has length %d, want 1", tlv.Length)
	}
	if tlv.Value[0] == 0 || tlv.Value[0] == 255 {
		return fmt.Errorf("bgp-ls-spf address family link descriptor TLV has reserved value %d", tlv.Value[0])
	}
	return nil
}
