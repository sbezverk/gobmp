package validator

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/kafka"
)

func buildMessgesMap(b []byte) (map[int][][]byte, error) {
	m := make(map[int][][]byte)
	for p := 0; p < len(b); {
		if p+8 > len(b) {
			return nil, fmt.Errorf("invalid length of byte array")
		}
		mt := binary.BigEndian.Uint32(b[p : p+4])
		glog.Infof("><SB> message type: %d", mt)
		// TODO (sbezverk) Checking message type against valid types would be great
		p += 4
		ml := binary.BigEndian.Uint32(b[p : p+4])
		glog.Infof("><SB> message length: %d", ml)
		p += 4
		if p+int(ml) > len(b) {
			return nil, fmt.Errorf("corrupted data")
		}
		glog.Infof("><SB> message: %s", string(b[p:p+int(ml)]))
		msgs, ok := m[int(mt)]
		if !ok {
			msgs = make([][]byte, 0)
		}
		msgs = append(msgs, b[p:p+int(ml)])
		p += int(ml)
	}
	for mt, msgs := range m {
		glog.Infof("For message type %d, %d messages found", mt, len(msgs))
	}

	return m, nil
}

func Check(topics []*kafka.TopicDescriptor, b []byte, errCh chan error) {
	_, err := buildMessgesMap(b)
	if err != nil {
		errCh <- err
		return
	}
	errCh <- nil
}
