package validator

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/kafka"
	bmp_message "github.com/sbezverk/gobmp/pkg/message"
)

func buildMessagesMap(b []byte) (map[int][][]byte, error) {
	m := make(map[int][][]byte)
	for p := 0; p < len(b); {
		if p+8 > len(b) {
			return nil, fmt.Errorf("invalid length of byte array, need at least 8 bytes for message type and length, got %d", len(b)-p)
		}
		mt := binary.BigEndian.Uint32(b[p : p+4])
		// Validate message type is in expected range (0 to bmp.BMPRawMsg)
		if mt > bmp.BMPRawMsg {
			return nil, fmt.Errorf("invalid message type: %d (expected 0-%d)", mt, bmp.BMPRawMsg)
		}
		p += 4
		ml := binary.BigEndian.Uint32(b[p : p+4])
		p += 4
		if p+int(ml) > len(b) {
			return nil, fmt.Errorf("corrupted data, expected %d bytes, but only %d bytes available", ml, len(b)-p)
		}
		msgs, ok := m[int(mt)]
		if !ok {
			msgs = make([][]byte, 0)
		}
		msgs = append(msgs, b[p:p+int(ml)])
		m[int(mt)] = msgs
		p += int(ml)
	}
	for mt, msgs := range m {
		glog.Infof("For message type %d, %d messages found", mt, len(msgs))
	}

	return m, nil
}

type check struct {
	stopCh chan struct{}
}

func makeUnicastPrefixKey(u *bmp_message.UnicastPrefix) (string, error) {
	if u == nil {
		return "", fmt.Errorf("object is nil")
	}
	return u.Prefix + "_" + strconv.Itoa(int(u.PrefixLen)) + "_" + u.PeerIP + "_" + u.Nexthop, nil
}

func (c *check) checkUnicastWorker(testMsgs [][]byte, topic *kafka.TopicDescriptor, done chan struct{}, workersErrChan chan error) {
	// Preparing message dictionary
	dictionary := make(map[string]*bmp_message.UnicastPrefix)
	for _, tm := range testMsgs {
		u := &bmp_message.UnicastPrefix{}
		if err := json.Unmarshal(tm, u); err != nil {
			workersErrChan <- err
			return
		}
		if u.IsEOR {
			continue
		}
		k, err := makeUnicastPrefixKey(u)
		if err != nil {
			workersErrChan <- err
			return
		}
		// Check for duplicate keys in test data
		if _, exists := dictionary[k]; exists {
			workersErrChan <- fmt.Errorf("duplicate key found in test data: %s", k)
			return
		}
		dictionary[k] = u
	}
	glog.Infof("Dictionary for topic type %d contains %d test messages", topic.TopicType, len(dictionary))
	// maxStaleMismatches is the number of times a key is allowed to arrive with
	// differing values before we treat it as a genuine failure.  A small budget
	// (e.g. 3) tolerates the 1-2 incomplete "early" messages that BMP active-mode
	// routers (e.g. FRR) sometimes publish before metadata is fully resolved,
	// while still failing fast when a real value mismatch persists.
	const maxStaleMismatches = 3
	matched := make(map[string]bool)
	mismatches := make(map[string]int)
	for {
		select {
		case <-c.stopCh:
			return
		case msg := <-topic.TopicChan:
			glog.Infof("Check received message from topic type: %d", topic.TopicType)
			ou := &bmp_message.UnicastPrefix{}
			if err := json.Unmarshal(msg, ou); err != nil {
				workersErrChan <- err
				return
			}
			if ou.IsEOR {
				continue
			}
			k, err := makeUnicastPrefixKey(ou)
			if err != nil {
				workersErrChan <- err
				return
			}
			u, ok := dictionary[k]
			if !ok {
				// Some BMP sessions produce transient or unexpected messages (e.g.
				// a withdrawal for a route that was briefly in a peer's adj-rib-in
				// during BGP convergence).  Log a warning and skip rather than
				// treating this as a hard failure, so the test remains focused on
				// verifying that all expected messages ARE received.
				glog.Warningf("received unexpected message for key: %s (not in test dictionary, skipping)", k)
				continue
			}
			// Skip messages that have already been matched by a later correct version.
			if matched[k] {
				continue
			}
			equal, diffs := u.Equal(ou)
			if !equal {
				mismatches[k]++
				if mismatches[k] >= maxStaleMismatches {
					workersErrChan <- fmt.Errorf("for key: %s, expected and received messages differ after %d attempts, diffs: %s",
						k, mismatches[k], strings.Join(diffs, " | "))
					return
				}
				glog.Warningf("key: %s values differ (stale message? attempt %d/%d), skipping: %s",
					k, mismatches[k], maxStaleMismatches, strings.Join(diffs, " | "))
				continue
			}
			glog.Infof("found matching the test message for the key: %s", k)
			matched[k] = true
			if len(matched) >= len(dictionary) {
				// All checks are completed, exiting
				glog.Infof("topic type %d, all checks are done.", topic.TopicType)
				done <- struct{}{}
				return
			}
		}
	}
}

func Check(topics []*kafka.TopicDescriptor, b []byte, stopCh chan struct{}, errCh chan error) {
	msgs, err := buildMessagesMap(b)
	if err != nil {
		errCh <- err
		return
	}
	c := &check{
		stopCh: make(chan struct{}),
	}
	doneCh := make(chan struct{}, len(topics))
	workersErrChan := make(chan error, len(topics))
	totalWorkers := 0
	for _, topic := range topics {
		topicMsgs, ok := msgs[topic.TopicType]
		if !ok {
			// Did not find corresponding to the topic type test messages
			errCh <- fmt.Errorf("no test messages for topic type: %d were found in the test data", topic.TopicType)
			close(c.stopCh)
			return
		}
		switch topic.TopicType {
		case bmp.UnicastPrefixV4Msg:
			fallthrough
		case bmp.UnicastPrefixMsg:
			fallthrough
		case bmp.UnicastPrefixV6Msg:
			go c.checkUnicastWorker(topicMsgs, topic, doneCh, workersErrChan)
			totalWorkers++
		}
	}
	if totalWorkers == 0 {
		errCh <- fmt.Errorf("no workers were started, likely due to unsupported topic types")
		return
	}
	done := 0
	for {
		select {
		case <-stopCh:
			close(c.stopCh)
			return
		case err := <-workersErrChan:
			close(c.stopCh)
			errCh <- err
			return
		case <-doneCh:
			done++
			if done >= totalWorkers {
				close(c.stopCh)
				errCh <- nil
				return
			}
		}
	}
}


