package srwallet

import (
	"errors"
	sr25519 "github.com/ChainSafe/go-schnorrkel"
	"regexp"
)

const (

	// MiniSecretKeyLength is the length of the MiniSecret Key
	MiniSecretKeyLength = 32

	// SecretKeyLength is the length of the SecretKey
	SecretKeyLength = 64
)

var (
	// suriRe is the regular expression for matching the Secret URI of format
	// <phrase><path>///<password>
	suriRe = regexp.MustCompile(`^(?P<phrase>[\d\w ]+)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$`)

	// pathRe is the regular expression for matching the parts of the path
	// component of the Secret URI
	pathRe = regexp.MustCompile(`/(/?[^/]+)`)

	// Errors
	ErrInvalidSURIFormat = errors.New("Secret URI format is invalid")
	ErrEmptyPhrase       = errors.New("The parsed Secret URI has an empty phrase")
	ErrInvalidByteLength = errors.New("An invalid number of bytes has been given")
)

// PhraseType specifies the type of data that was passed as the phrase component
// in a Secret URI
type PhraseType int

const (
	SecretHex PhraseType = iota +1
	SS58Public
	Mnemonic
)


// SecretURI defines a struct consisting of the parts of a Secret URI
type SecretURI struct {
	Phrase   string
	Path     string
	Password string
	Network  Network
	Type PhraseType
}

type DerivablePrivateKey bool


// NewSecretURI takes a given string Secret URI and splits it into Phrase, Path,
// and Password components given the format <phrase><path>///<password> and
// returns it as a struct
func NewSecretURI(suri string, net Network) (*SecretURI, error) {

	// validate network option
	_, err := GetNetworkVersion(net)

	if err != nil {
		return nil, err
	}

	data := &SecretURI{
		Network: net,
	}

	res := suriRe.FindStringSubmatch(suri)

	if res == nil {
		return data, ErrInvalidSURIFormat
	}

	data.Phrase = res[1]
	data.Path = res[2]
	data.Password = res[5]

	if data.Phrase == "" {
		return data, ErrEmptyPhrase
	}

	return data, nil
}

// DerivableKey returns a DerivableKey from the Secret URI
func (s *SecretURI) DerivableKey() (sr25519.DerivableKey, DerivablePrivateKey, error) {

	if b, ok := DecodeHex(s.Phrase, s.Network.AddressPrefix()); ok {
		// hex encoded secret
		s.Type = SecretHex
		var raw [32]byte

		switch len(b) {

		case MiniSecretKeyLength:
			copy(raw[:], b)

		case SecretKeyLength:
			// drop the nonce (bytes 32-64) to convert into MiniSecretKey
			copy(raw[:], b[:32])

		default:
			// unexpected number of bytes
			return nil, false, ErrInvalidByteLength
		}

		ms, err := sr25519.NewMiniSecretKeyFromRaw(raw)

		if err != nil {
			return nil, false, err
		}

		return  ms.ExpandEd25519(),  true, nil

	} else if raw, err := DecodeSS58Address(s.Phrase, s.Network, SS58Checksum); err == nil {
		// ss58 encoded public address
		s.Type = SS58Public
		return sr25519.NewPublicKey(raw),  false, nil

	} else {
		// mnemonic word list
		s.Type = Mnemonic
		ms, err := sr25519.MiniSecretFromMnemonic(s.Phrase, s.Password)

		if err != nil {
			return nil, false, err
		}
		/*
msSec := ms.Encode()
fmt.Println("ms secret=",hex.EncodeToString(msSec[:]))
sec := ms.ExpandEd25519()
secEnc := sec.Encode()
		fmt.Println("expanded secret=",hex.EncodeToString(secEnc[:]))
*/
		return  ms.ExpandEd25519(), true, nil
	}
}

// GetJunctions returns the junction parts of the path component of the Secret
// URI.
func (s *SecretURI) GetJunctions() ([]*junction, error) {
	data := make([]*junction, 0)

	for _, part := range s.pathParts() {
		jun, err := newJunction(part)

		if err != nil {
			return nil, err
		}

		data = append(data, jun)
	}

	return data, nil
}

// pathParts takes the path component from the Secret URI used for HD key
// derivation and returns it split into its component paths, eg:
// given path of "//joe//polkadot//0" it will return [/joe /polkadot /0]
// or a second path using soft keys of "/joe/polkadot/0" will return
// [joe polkadot 0]
func (s *SecretURI) pathParts() []string {

	parts := make([]string, 0)

	res := pathRe.FindAllStringSubmatch(s.Path, -1)

	for _, p := range res {
		parts = append(parts, p[1])
	}

	return parts
}
