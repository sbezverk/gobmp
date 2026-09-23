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
	if operation == AddPrefix {
		if err := validateLSNLRI80(parsed, update); err != nil {
			glog.Errorf("invalid bgp-ls-spf NLRI: %+v", err)
			// Per RFC 9815 Section 7.1, malformed NLRIs are treated as withdrawn.
			if update != nil {
				p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: parsed}, DelPrefix, ph, update)
			}
			return
		}
	}
	p.processNLRI71SubTypes(nlri71View{MPNLRI: nlri, nlri: parsed}, operation, ph, update)
}

func validateLSNLRI80(nlri *ls.NLRI71, update *bgp.Update) error {
	if nlri == nil {
		return fmt.Errorf("bgp-ls-spf NLRI is nil")
	}
	if update == nil {
		return fmt.Errorf("bgp-ls-spf update is nil")
	}
	for _, element := range nlri.NLRI {
		if err := validateLSNLRI80Element(element); err != nil {
			return err
		}
	}

	attribute, err := update.GetBGPLSAttribute()
	if err != nil {
		var missing *bgp.AttributeNotFoundError
		if errors.As(err, &missing) {
			// RFC 9815 Section 7.1 retains NLRIs after BGP-LS Attribute
			// discard, although a BGP speaker must not use them for SPF.
			return nil
		}
		return fmt.Errorf("invalid bgp-ls attribute: %w", err)
	}
	if err := validateLSNLRI80Attribute(attribute); err != nil {
		return err
	}
	for _, element := range nlri.NLRI {
		if err := validateLSNLRI80Metric(element.Type, attribute); err != nil {
			return err
		}
		if element.Type >= 1 && element.Type <= 4 {
			if err := validateLSNLRI80Status(attribute); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateLSNLRI80Element(element ls.Element) error {
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
	case 3, 4:
		prefix, ok := element.LS.(*base.PrefixNLRI)
		if !ok {
			return fmt.Errorf("bgp-ls-spf prefix NLRI has unexpected type %T", element.LS)
		}
		return validateLSNLRI80NodeDescriptor(prefix.LocalNode)
	}
	return nil
}

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

func validateLSNLRI80Metric(nlriType uint16, attribute *bgpls.NLRI) error {
	metricType := uint16(0)
	switch nlriType {
	case 2:
		metricType = bgpLSIGPMetricTLV
	case 3, 4:
		metricType = bgpLSPrefixMetricTLV
	default:
		return nil
	}
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
		return fmt.Errorf("bgp-ls-spf NLRI type %d requires metric TLV %d", nlriType, metricType)
	}
	return nil
}

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
