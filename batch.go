package srkeyring

import (
	"errors"
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

var (
	ErrDecodingSignature = errors.New("Error decoding signature")
)

// BatchVerifier defines the struct for batch verifying signatures with a
// 300 percent speed up versus verifying signatures via a loop
type BatchVerifier struct {
	ver *sr25519.BatchVerifier
}

// NewBatchVerifier returns a new batchVerifier used for batch verifying
// signatures
func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{
		ver: sr25519.NewBatchVerifier(),
	}
}

// Add a signature, keyring, and its transcript message to the batch
func (b *BatchVerifier) Add(t *merlin.Transcript, signature [64]byte,
	kr *KeyRing) error {

	sig := new(sr25519.Signature)

	if err := sig.Decode(signature); err != nil {
		return ErrDecodingSignature
	}

	return b.ver.Add(t, sig, kr.pub)
}

// Verify the batch of signatures
func (b *BatchVerifier) Verify() bool {
	return b.ver.Verify()
}
