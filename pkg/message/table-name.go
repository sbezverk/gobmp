package message

import "github.com/sbezverk/gobmp/pkg/bmp"

// getTableName returns the Loc-RIB table name from Informational TLV type 3
// using the header's complete table key (RFC 9069 §5.2.1).
func (p *producer) getTableName(ph *bmp.PerPeerHeader) string {
	if ph == nil {
		return ""
	}
	p.tableLock.RLock()
	defer p.tableLock.RUnlock()

	tableKey := ph.GetTableKey()
	tn := ""

	if properties, ok := p.tableProperties[tableKey]; ok {
		for _, tlv := range properties.tableInfoTLVs {
			if tlv.InformationType == 3 {
				// Information is []byte, convert to string.
				tn += string(tlv.Information)
			}
		}
	}

	return tn
}
