// Package srkeyring provides functions to implementation HDKD
// (Hierarchical Deterministic Key Derivation) using sr25519
// (Schnorr over Ristretto25519).
//
// Compatible with Substrates key generation and command line utility subkey.
//
// Supports SS58 address formatting and SecretURI key derivation format
// specified as;
// `<mnemonic, mini-secret, or SS58 address>[//hard-derivation][/soft-derivation][///password]`.
package srkeyring

import (
	"errors"
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"github.com/cosmos/go-bip39"
	"github.com/gtank/merlin"
)

var (
	ErrDecodingSecretHex = errors.New("Error decoding secret hex phrase")
	ErrUnknownPhraseType = errors.New("SURI phrase type is unknown or not set")
	ErrSeedNotAvailable  = errors.New("Unable to get seed from public address data")
	ErrInvalidWordCount  = errors.New("An invalid WordCount was given, valid values are 12, 15, 18, 21, or 24")
	ErrNonMnemonic       = errors.New("Error KeyRing was generated from non mnemonic source")
)

// KeyRing defines a key pair from a derive Secret URI
type KeyRing struct {
	// secret is the private key
	secret *sr25519.SecretKey
	// pun is the public key
	pub *sr25519.PublicKey
	// hasSecret is a flag to indicate if the KeyRing has a "secret" private key
	// value set.  If only Soft derivation was done then only the public key
	// is available
	hasSecret bool
	// suri is the parsed SecretURI
	suri *SecretURI
	// seed is the seed used to create the SecretKey from the last derived
	// ExtendedKey when the SecretURI has Hard component paths set
	seed [32]byte
	// hasSeed is a flag to indicate if a seed is set
	hasSeed bool
}

// WordCount defines the type for specifying the number of words in a mnemonic.
// Valid values are 12, 15, 18, 21, or 24 words
type WordCount int

// entropyBits defines the bitsize for entropy for a mnemonic
type entropyBits int

// entropyWords is a map to define the amount of entropy required for the given
// number of words in a mnemonic to generate
var entropyWords = map[WordCount]entropyBits{
	12: 128,
	15: 160,
	18: 192,
	21: 224,
	24: 256,
}

// Generate creates a new KeyRing with a randomly created mnemonic of the
// specified number of words
func Generate(words int, net Network) (*KeyRing, error) {

	// check word count is valid
	bitsize, ok := entropyWords[WordCount(words)]

	if !ok {
		return nil, ErrInvalidWordCount
	}

	// create entropy and mnemonic
	entropy, err := bip39.NewEntropy(int(bitsize))

	if err != nil {
		return nil, err
	}

	mnemonic, err := bip39.NewMnemonic(entropy)

	if err != nil {
		return nil, err
	}

	return FromURI(mnemonic, net)
}

// FromPublic returns a KeyRing from the raw bytes of a public key
func FromPublic(b [32]byte, net Network) (*KeyRing, error) {
	kr := &KeyRing{
		suri: &SecretURI{
			Network: net,
			Type:    RawPublicKey,
		},
		pub: sr25519.NewPublicKey(b),
	}

	return kr, nil
}

// FromURI returns a KeyRing from the given Secret URI
func FromURI(str string, net Network) (*KeyRing, error) {

	var err error

	suri, err := NewSecretURI(str, net)

	if err != nil {
		return nil, err
	}

	dvKey, dvPrivate, err := suri.DerivableKey()

	if err != nil {
		return nil, err
	}

	junctions, err := suri.GetJunctions()

	if err != nil {
		return nil, err
	}

	var exKey *sr25519.ExtendedKey
	var msKey *sr25519.MiniSecretKey
	// allPathsHard is a flag to indicate if all path junctions are Hard. If
	// they are, then the secret Seed can be derived from the MiniSecretKey
	allPathsHard := true

	for _, jun := range junctions {

		if jun.hard {
			if dvPrivate {
				// as we want access to the MiniSecretKey seed we don't use
				// the sr25519.DeriveKeyHard() function here as it only returns
				// us the ExtendedKey as a SecretKey.
				exKey, msKey, err = deriveHardMiniKey(dvKey, nil, jun.chainCode)
			} else {
				exKey, err = sr25519.DeriveKeyHard(dvKey, nil, jun.chainCode)
			}

		} else {
			// soft key
			allPathsHard = false
			exKey, err = sr25519.DeriveKeySimple(dvKey, nil, jun.chainCode)
		}

		if err != nil {
			return nil, err
		}

		if dvPrivate {
			dvKey, err = exKey.Secret()
		} else {
			dvKey, err = exKey.Public()
		}

		if err != nil {
			return nil, err
		}
	}

	kr := &KeyRing{
		hasSecret: bool(dvPrivate),
		suri:      suri,
	}

	// if the suri provided secret input, or if the suri provided a public
	// key/address or secret and included a path (with junctions) to derive from
	if dvPrivate {
		// private key secret was provided
		kr.secret = dvKey.(*sr25519.SecretKey)
		kr.pub, err = dvKey.(*sr25519.SecretKey).Public()

		if err != nil {
			return nil, err
		}

		if allPathsHard && len(junctions) > 0 {
			kr.seed = msKey.Encode()
			kr.hasSeed = true
		}

	} else {
		// public key was provided
		kr.pub = dvKey.(*sr25519.PublicKey)
	}

	return kr, nil
}

// deriveHardMiniKey implements similar functionality to sr25519.DeriveKeyHard()
// but allows us to retain the MiniKey created during the process from which
// we can set the Seed entropy from.
func deriveHardMiniKey(key sr25519.DerivableKey, i []byte, cc [32]byte) (
	*sr25519.ExtendedKey, *sr25519.MiniSecretKey, error) {

	msKey, resCC, err := key.(*sr25519.SecretKey).HardDeriveMiniSecretKey(i, cc)

	if err != nil {
		return nil, nil, err
	}

	exKey := sr25519.NewExtendedKey(msKey.ExpandEd25519(), resCC)

	return exKey, msKey, nil
}

// Sign signs the message using the secret key
func (k *KeyRing) Sign(t *merlin.Transcript) (signature [64]byte, err error) {
	sig, err := k.secret.Sign(t)

	if err != nil {
		return signature, err
	}

	return sig.Encode(), nil
}

// Verify the message against the signature
func (k *KeyRing) Verify(t *merlin.Transcript, signature [64]byte) bool {
	sig := new(sr25519.Signature)

	if err := sig.Decode(signature); err != nil {
		return false
	}

	return k.pub.Verify(sig, t)
}

// SigningContext returns the transcript used for message signing for the
// Network set
func (k *KeyRing) SigningContext(msg []byte) *merlin.Transcript {
	return sr25519.NewSigningContext([]byte(k.suri.Network.Name()), msg)
}

// Public returns the public key in raw bytes
func (k *KeyRing) Public() [32]byte {
	return k.pub.Encode()
}

// PublicHex returns the public key hex encoded
func (k *KeyRing) PublicHex() string {
	pub := k.Public()
	return EncodeHex(pub[:], k.suri.Network.AddressPrefix())
}

// Mnemonic returns the mnemonic phrase if the KeyRing was generated by a
// mnemonic phrase or an error if generated by other source
func (k *KeyRing) Mnemonic() (string, error) {
	if k.suri.Type == Mnemonic {
		return k.suri.Phrase, nil
	}

	return "", ErrNonMnemonic
}

// Secret returns the private secret key in raw bytes
func (k *KeyRing) Secret() [32]byte {
	return k.secret.Encode()
}

// SecretHex returns the private secret key hex encoded
func (k *KeyRing) SecretHex() string {
	pri := k.Secret()
	return EncodeHex(pri[:], k.suri.Network.AddressPrefix())
}

// SS58Address returns the public key encoded as a SS58 address
func (k *KeyRing) SS58Address() (string, error) {
	return SS58Address(k.Public(), k.suri.Network, SS58Checksum)
}

// Seed returns the seed generated from the mnemonic in raw bytes
func (k *KeyRing) Seed() ([32]byte, error) {
	var res [32]byte

	switch k.suri.Type {
	case SecretHex:
		if k.hasSeed {
			// seed was derived from extended key due to suri Hard paths
			return k.seed, nil
		}

		// decode the seed from suri Phrase when no Path is set
		seed, ok := DecodeHex(k.suri.Phrase, k.suri.Network.AddressPrefix())

		if !ok {
			return res, ErrDecodingSecretHex
		}

		switch len(seed) {
		case MiniSecretKeyLength:
			copy(res[:], seed)

		case SecretKeyLength:
			copy(res[:], seed[:32])

		default:
			return res, ErrDecodingSecretHex
		}

		return res, nil

	case SS58Public, RawPublicKey:
		return res, ErrSeedNotAvailable

	case Mnemonic:
		if k.hasSeed {
			// seed was derived from extended key due to suri Hard paths
			return k.seed, nil
		}

		// calculate seed from suri Phrase when no Path is set
		seed, err := sr25519.SeedFromMnemonic(k.suri.Phrase, k.suri.Password)

		if err != nil {
			return res, err
		}

		copy(res[:], seed[:32])
		return res, nil

	default:
		return res, ErrUnknownPhraseType
	}
}

// SeedHex returns the seed generated from the mnemonic hex encoded
func (k *KeyRing) SeedHex() (string, error) {
	raw, err := k.Seed()
	return EncodeHex(raw[:], k.suri.Network.AddressPrefix()), err
}

// VrfSign creates a signed output and proof
func (k *KeyRing) VrfSign(t *merlin.Transcript) (output [32]byte, proof [64]byte, err error) {
	out, prf, err := k.secret.VrfSign(t)

	if err != nil {
		return output, proof, err
	}

	return out.Output().Encode(), prf.Encode(), nil
}

// VrfVerify verifies if the given proof and output are valid against the
// public key
func (k *KeyRing) VrfVerify(t *merlin.Transcript, output [32]byte, proof [64]byte) (
	bool, error) {

	out := sr25519.NewOutput(output)
	inout := out.AttachInput(k.pub, t)

	prf := new(sr25519.VrfProof)
	err := prf.Decode(proof)

	if err != nil {
		return false, err
	}

	return k.pub.VrfVerify(t, inout, prf)
}
