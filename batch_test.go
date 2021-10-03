package srkeyring

import (
	"fmt"
	"testing"
)

func TestBatchVerifierValid(t *testing.T) {
	// number of signatures and keypairs to generate
	c := 12
	// message to sign
	msg := []byte("hello")

	ver, err := createBatch(c, msg)

	if err != nil {
		t.Fatalf("Error creating test batch: %v", err)
	}

	if !ver.Verify() {
		t.Error("Batch verifier failed, invalid signature set")
	}
}

func createBatch(c int, msg []byte) (*BatchVerifier, error) {

	ver := NewBatchVerifier()

	for i := 0; i < c; i++ {
		kr, err := Generate(12, NetSubstrate{})

		if err != nil {
			return nil, fmt.Errorf("Error generating keyring: %w", err)
		}

		sig, err := kr.Sign(kr.SigningContext(msg))

		if err != nil {
			return nil, fmt.Errorf("Error signing message: %w", err)
		}

		err = ver.Add(kr.SigningContext(msg), sig, kr)

		if err != nil {
			return nil, fmt.Errorf("Error adding to batch verifier: %w", err)
		}
	}

	return ver, nil
}

func TestBatchVerifierInvalid(t *testing.T) {
	// number of signatures and keypairs to generate
	c := 7
	// message to sign
	msg := []byte("the protocols")

	ver := NewBatchVerifier()

	for i := 0; i < c; i++ {
		kr, err := Generate(12, NetSubstrate{})

		if err != nil {
			t.Fatalf("Error generating keyring: %v", err)
		}

		var sig [64]byte

		// corrupt the message of the 4th
		if i == 3 {
			sig, err = kr.Sign(kr.SigningContext([]byte("different msg")))
		} else {
			sig, err = kr.Sign(kr.SigningContext(msg))
		}

		if err != nil {
			t.Fatalf("Error signing message: %v", err)
		}

		err = ver.Add(kr.SigningContext(msg), sig, kr)

		if err != nil {
			t.Fatalf("Error adding to batch verifier: %v", err)
		}
	}

	if ver.Verify() {
		t.Error("Batch verifier succeeded, but failure expected")
	}
}

var batchVerifyVars = struct {
	// number of signatures and keypairs to generate
	sigNum int
	// message to sign
	msg []byte
}{
	sigNum: 20,
	msg:    []byte("hello"),
}

// BenchmarkBatchVerifier uses the BatchVerifier to benchmark 20 signatures
func BenchmarkBatchVerifier(b *testing.B) {
	b.ReportAllocs()

	ver, err := createBatch(batchVerifyVars.sigNum, batchVerifyVars.msg)

	if err != nil {
		b.Fatalf("Error creating test batch: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		_ = ver.Verify()
	}
}

// BenchmarkBatchLoop uses each individual keyrings verification in a loop to
// test all signatures to form a comparison to the BatchVerifier performance
func BenchmarkBatchLoop(b *testing.B) {
	b.ReportAllocs()

	keys := make([]*KeyRing, 0)
	sigs := make([][64]byte, 0)

	for i := 0; i < batchVerifyVars.sigNum; i++ {
		kr, err := Generate(12, NetSubstrate{})

		if err != nil {
			b.Fatalf("Error generating keyring: %v", err)
		}

		sig, err := kr.Sign(kr.SigningContext(batchVerifyVars.msg))

		if err != nil {
			b.Fatalf("Error signing message: %v", err)
		}

		keys = append(keys, kr)
		sigs = append(sigs, sig)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for i, kr := range keys {
			_ = kr.Verify(kr.SigningContext(batchVerifyVars.msg), sigs[i])
		}
	}
}
