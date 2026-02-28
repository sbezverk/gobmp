package kafka

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/IBM/sarama"
	"github.com/xdg-go/scram"
)

var (
	// SHA256 hasher for SCRAM-SHA-256.
	SHA256 scram.HashGeneratorFcn = sha256.New
	// SHA512 hasher for SCRAM-SHA-512.
	SHA512 scram.HashGeneratorFcn = sha512.New
)

// xdgSCRAMClient adapts github.com/xdg-go/scram to sarama.SCRAMClient.
// A new instance must be used per connection (sarama calls SCRAMClientGeneratorFunc for each broker).
type xdgSCRAMClient struct {
	*scram.Client
	*scram.ClientConversation
	hashGen scram.HashGeneratorFcn
}

func (x *xdgSCRAMClient) Begin(userName, password, authzID string) (err error) {
	x.Client, err = x.hashGen.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	x.ClientConversation = x.Client.NewConversation()
	return nil
}

func (x *xdgSCRAMClient) Step(challenge string) (response string, err error) {
	return x.ClientConversation.Step(challenge)
}

func (x *xdgSCRAMClient) Done() bool {
	return x.ClientConversation.Done()
}

// SCRAMClientGeneratorSHA256 returns a generator for SCRAM-SHA-256 (one client per connection).
func SCRAMClientGeneratorSHA256() sarama.SCRAMClient {
	return &xdgSCRAMClient{hashGen: SHA256}
}

// SCRAMClientGeneratorSHA512 returns a generator for SCRAM-SHA-512 (one client per connection).
func SCRAMClientGeneratorSHA512() sarama.SCRAMClient {
	return &xdgSCRAMClient{hashGen: SHA512}
}
