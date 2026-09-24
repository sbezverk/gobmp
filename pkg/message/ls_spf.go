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
	bgpLSSPFSequenceNumberTLV = 1181
	bgpLSSPFStatusTLV         = 1184
	bgpLSIGPMetricTLV         = 1095
	bgpLSPrefixMetricTLV      = 1155
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
// Element types outside RFC 9815's defined set are rejected rather than
// published unvalidated.
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
		return validateLSNLRI80Metric(bgpLSIGPMetricTLV, attribute)
	case 3, 4:
		prefix, ok := element.LS.(*base.PrefixNLRI)
		if !ok {
			return fmt.Errorf("bgp-ls-spf prefix NLRI has unexpected type %T", element.LS)
		}
		if prefix.ProtocolID != base.Direct {
			return fmt.Errorf("bgp-ls-spf prefix NLRI has protocol ID %d, want %d", prefix.ProtocolID, base.Direct)
		}
		if err := validateLSNLRI80NodeDescriptor(prefix.LocalNode); err != nil {
			return err
		}
		return validateLSNLRI80Metric(bgpLSPrefixMetricTLV, attribute)
	default:
		return fmt.Errorf("bgp-ls-spf NLRI element type %d is not supported", element.Type)
	}
}

// validateLSNLRI80NodeDescriptor checks the mandatory BGP Router ID (512)
// and BGP Confederation Member AS Number (516) sub-TLVs per RFC 9815
// Section 5.2.1.
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
		if !ok || tlv.Length != typeAndLength.length || len(tlv.Value) != int(typeAndLength.length) {
			return fmt.Errorf("node descriptor requires TLV %d with length %d", typeAndLength.typeID, typeAndLength.length)
		}
	}
	return nil
}

// validateLSNLRI80Attribute checks that the BGP-LS Attribute carries exactly
// one well-formed SPF Sequence Number TLV (1181) per RFC 9815 Section 5.2.2.
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

// validateLSNLRI80Metric checks that the BGP-LS Attribute carries a
// well-formed, mandatory four-octet metric TLV of the given type, per
// RFC 9815 Section 5.2.2.
func validateLSNLRI80Metric(metricType uint16, attribute *bgpls.NLRI) error {
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
	if !found {
		return fmt.Errorf("bgp-ls-spf NLRI requires metric TLV %d", metricType)
	}
	return nil
}

// validateLSNLRI80Status checks that the BGP-LS Attribute carries exactly
// one well-formed, non-reserved SPF Status TLV (1184) per RFC 9815
// Section 5.2.2. The Status TLV is mandatory for every BGP-LS-SPF Update.
func validateLSNLRI80Status(attribute *bgpls.NLRI) error {
	found := false
	for _, tlv := range attribute.LS {
		if tlv.Type != bgpLSSPFStatusTLV {
			continue
		}
		found = true
		if tlv.Length != 1 || len(tlv.Value) != 1 {
			return fmt.Errorf("bgp-ls-spf status TLV has length %d, want 1", tlv.Length)
		}
		if tlv.Value[0] == 0 || tlv.Value[0] == 255 {
			return fmt.Errorf("bgp-ls-spf status TLV has reserved value %d", tlv.Value[0])
		}
	}
	if !found {
		return fmt.Errorf("bgp-ls-spf NLRI requires status TLV %d", bgpLSSPFStatusTLV)
	}
	return nil
}
