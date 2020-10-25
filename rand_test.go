package srwallet

import (
	"encoding/hex"
	"fmt"
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"testing"
)

func TestDebug(t *testing.T) {
/*
	msg := []byte("hello friends")
	signingCtx := []byte("example")

	signingTranscript := sr25519.NewSigningContext(signingCtx, msg)
	verifyTranscript := sr25519.NewSigningContext(signingCtx, msg)

	priv, pub, err := sr25519.GenerateKeypair()
	if err != nil {
		fmt.Println(err)
		return
	}

	sig, err := priv.Sign(signingTranscript)
	if err != nil {
		fmt.Println(err)
		return
	}

	ok := pub.Verify(sig, verifyTranscript)
	if !ok {
		fmt.Println("did not verify :(")
		return
	}
	fmt.Println("done")
 */

	msg := []byte("message")
	signingCtx := []byte("substrate")

	verifyTranscript := sr25519.NewSigningContext(signingCtx, msg)

	pubHex := "0x38c9aaacbf915cdd41e91eb13d3921af7d478e8c9dea39d469805b0ad9c8ff75"
	pubBytes, err := hex.DecodeString(pubHex[2:])

	if err != nil {
		t.Fatalf("Error decoding pub key hex bytes: %v", err)
	}

	var pub32 [32]byte
	copy(pub32[:], pubBytes)
	pub := sr25519.NewPublicKey(pub32)

	pubEnc := pub.Encode()
	fmt.Println("pub key=", pubEnc)
	fmt.Println("pub key hex=", hex.EncodeToString(pubEnc[:]))

	sigHex := "f00e0118484ebaf78c8bb5ed1955b6b3dfc22805af72d1f396b0a88ceea26d7bfb3d03e01574bc3a092cbfef5d80966b8650ec47992113e4bb40e9b95b1a018d"
	sigBytes, err := hex.DecodeString(sigHex)

	if err != nil {
		t.Fatalf("Error decoding signature hex: %v", err)
	}

	var sig64 [64]byte
	copy(sig64[:], sigBytes)
	sig := &sr25519.Signature{}
	err = sig.Decode(sig64)

	if err != nil {
		t.Fatalf("Error decoding singature: %v", err)
	}

	ok := pub.Verify(sig, verifyTranscript)
	if !ok {
		fmt.Println("did not verify :(")
		//return
	}

	// sign
	suri := "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral"
	kr, err  := KeyRingFromURI(suri, NetSubstrate)

	fmt.Println("kr pub=",kr.pub.Encode() )

	// https://github.com/ChainSafe/gossamer/blob/09c27233162157ff7d45f78fc1e7e4e28ec8050c/lib/crypto/sr25519/sr25519.go
	signingTranscript := sr25519.NewSigningContext(signingCtx, msg)

	mySig, err := kr.secret.Sign(signingTranscript)
	if err != nil {
		t.Fatalf("Error signing: %v", err)
	}

	mySigBytes := mySig.Encode()
	fmt.Println("mySig = ", hex.EncodeToString(mySigBytes[:]))


	fmt.Println("done")

}