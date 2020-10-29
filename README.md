# srkeyring

<p>
  <a href="https://github.com/swdee/srkeyring/actions?query=workflow%3A%22Test+Code+Matrix%22"><img src="https://github.com/swdee/srkeyring/workflows/Test%20Code%20Matrix/badge.svg"></a>
  <a href="https://github.com/swdee/srkeyring/actions?query=workflow%3A%22Lint+Code%22"><img src="https://github.com/swdee/srkeyring/workflows/Lint%20Code/badge.svg"></a>
</p>

Provides Go functions for implementing HDKD (Hierarchical Deterministic Key Derivation) using
sr25519 (Schnorr over Ristretto25519) which is compatible with 
[Substrates](https://github.com/paritytech/substrate) sr25519 
key generation and command line utility 
[subkey](https://www.substrate.io/kb/integrate/subkey).

Supports Substrates [SecretURI](https://polkadot.js.org/docs/keyring/start/suri/) key derivation format specified as 
`<mnemonic, mini-secret, or SS58 address>[//hard-derivation][/soft-derivation][///password]`
and [SS58](https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)) 
public address formatting.


## Requirements

Go v1.13 or newer

## Usage

```bash
go get -u github.com/swdee/srkeyring
```

## Examples

**Note:** In the following examples error handling is ignored for brevity.


### New KeyRing

Generate new KeyRing (Private and Public keys) from randomly generated Mnemonic 
of specified word count.

```go
package main

import (
    "github.com/swdee/srkeyring"  
    "log"    
)

func main() {
    // generate keyring with random 12 word mnemonic
    kr, _ := srkeyring.Generate(12, srkeyring.NetSubstrate{})

    // output keyring details
    mnemonic, _ := kr.Mnemonic()
    seed, _ := kr.SeedHex()
    pub := kr.PublicHex()
    ss58, _ := kr.SS58Address()  

    log.Printf("Mnemonic Phrase: %s", mnemonic)
    log.Printf("Seed: %s", seed)
    log.Printf("Public Key: %x", pub)
    log.Printf("SS58 Address: %s", ss58)
}
```


### KeyRing from Secret URI with Signing 

Create KeyRing from Secret URI, output public SS58
address, and sign message.  Verification of signature is performed from KeyRing
generated from public SS58 formatted address.

```go
package main

import (
    "github.com/swdee/srkeyring"  
    "log"    
)

func main() {
    // generate keyring from 12 word mnemonic
    secretURI := "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral"
    kr, _ := srkeyring.FromURI(secretURI, srkeyring.NetSubstrate{})

    // output public SS58 formatted address
    ss58, _ := kr.SS58Address()  
    log.Printf("SS58 Address: %s", ss58)

    // sign message
    msg := []byte("setec astronomy")
    sig, _ := kr.Sign(kr.SigningContext(msg))
        
    // create new keyring from SS58 public address to verify message signature
    verkr, _ := srkeyring.FromURI(ss58, srkeyring.NetSubstrate{})
    
    if !verkr.Verify(verkr.SigningContext(msg), sig) {
        log.Fatalf("Error invalid signature for message")
    } else {
        log.Print("Signature is valid!")
    }
}
```

### Hard/Soft Key Derivation

A more complex example uses Hard and Soft key derivation for generating 
a Master KeyRing from which Child KeyRing's are created.  This enables the 
following type of scenario;

- Master KeyRing is held by company executives and enables them to control
all Child and GrandChild keys.
- Child KeyRing is generated from Master KeyRing and given to the Website Development
department of a Company, enabling them to control all GrandChild keys.
- GrandChild KeyRing is created from Child KeyRing public address to create unique
addresses to receive payments on the companies ecommerce website. 

This hierarchical structure provides privilege separation within the company. 
Only public keys are present on the website servers, so no 
private keys are recoverable if the server infrastructure is hacked.  The Website
Development department only has control over GrandChild keys under its department
and no other departments Child keys within the company. 
   

```go
package main

import (
    "github.com/swdee/srkeyring"     
    "fmt"
    "log"
)

func main() {
	// generate master keyring with random 24 word mnemonic
	masterKr, _ := srkeyring.Generate(24, srkeyring.NetSubstrate{})
	masterMnemonic, _ := masterKr.Mnemonic()

	// generate child keyring for website development department using Hard key
	childUri := fmt.Sprintf("%s//webdev", masterMnemonic)
	childKr, _ := srkeyring.FromURI(childUri, srkeyring.NetSubstrate{})

	// seed from child keyring is provided to website development department
	// if you would like them to have control over grandchild keyring's
	webdevSeed, _ := childKr.SeedHex()

	// if no control is to be given to website development department then only
	// provide the child KeyRing's public SS58 address
	webdevSS58, _ := childKr.SS58Address()

	// website is configured to generate unique addresses through grandchild keys
	// to receive payment from the child keyring's public ss58 address using
	// a Soft key
	payUri := fmt.Sprintf("%s/payment/42", webdevSS58)
	payKr, _ := srkeyring.FromURI(payUri, srkeyring.NetSubstrate{})

	// payment address is given to customer
	payAddr, _ := payKr.SS58Address()

	// the website development department can then generate the payment address
	// using Secret URI
	webdevClaimUri := fmt.Sprintf("%s/payment/42", webdevSeed)

	// payment address can be generated from master keyring using Secret URI
	masterClaimUri := fmt.Sprintf("%s//webdev/payment/42", masterMnemonic)

	log.Printf("payAddr: %s", payAddr)
	log.Printf("webdevClaimUri: \"%s\"", webdevClaimUri)
	log.Printf("masterClaimUri: \"%s\"", masterClaimUri)
}
```
 
 
### Alternative Networks

This library only implements key generation for the Substrate network, to generate
keys for other networks such as Polkadot Mainnet implement the Network interface.


```go
package main

import (
	"github.com/swdee/srkeyring"
	"log"
)

func main() {
	// generate keyring with random 12 word mnemonic
	kr, _ := srkeyring.Generate(12, NetPolkadot{})

	// output keyring details
	mnemonic, _ := kr.Mnemonic()
	seed, _ := kr.SeedHex()
	pub := kr.PublicHex()
	ss58, _ := kr.SS58Address()

	log.Printf("Mnemonic Phrase: %s", mnemonic)
	log.Printf("Seed: %s", seed)
	log.Printf("Public Key: %s", pub)
	log.Printf("SS58 Address: %s", ss58)
}

// force NetPolkadot to implement Network interface
var _ srkeyring.Network = &NetPolkadot{}

// NetPolkadot implements the Network interface to define polkadots mainnet
// settings
type NetPolkadot struct{}

// Name returns the network name used in the KeyRing SigningContext transcript
func (n NetPolkadot) Name() string {
	return "polkadot"
}

// Version returns the network version number used in SS58 address formatting
func (n NetPolkadot) Version() uint8 {
	return 0
}

// AddressPrefix returns a prefix to apply to hex encoded addresses for
// public key and private seed
func (n NetPolkadot) AddressPrefix() srkeyring.HexPrefix {
	return "0x"
}

// ChecksumStart is the starting byte position of the blake2d checksum
// calculated when generating the SS58 address checksum
func (n NetPolkadot) ChecksumStart() int {
	return 0
}

// ChecksumEnd is the end byte position of the blake2d checksum
// calculated when generating the SS58 address checksum
func (n NetPolkadot) ChecksumEnd() int {
	return 2
}
````

## Benchmark

A comparison between regular Sign/Verify and VRF equivalents show the addition 
overhead involved with the VRF scheme.

```
$ go test -bench=.

BenchmarkSign-8             9520            142143 ns/op            1784 B/op         38 allocs/op
BenchmarkVerify-8           6644            175140 ns/op            1408 B/op         30 allocs/op
BenchmarkVrfSign-8          2770            429305 ns/op            2656 B/op         59 allocs/op
BenchmarkVrfVerify-8        3753            319850 ns/op            5320 B/op         51 allocs/op
```


## Inspiration

This library started off as a refactor of 
[go-subkey](https://github.com/vedhavyas/go-subkey)
with the following enhancements and changes.

- Decoding of SS58 Addresses to raw bytes
- Unit testing across entire code based
- Shifted overlap of Soft and Hard key derivation to upstream 
  package [go-schnorrkel](github.com/ChainSafe/go-schnorrkel) in 
  [#PR19](https://github.com/ChainSafe/go-schnorrkel/pull/19)
- Supports deriving child public keys from public SS58 address
- Convenience functions to output Public and Secret keys hex encoded
- Functions to access KeyRing Seed bytes
- Added VRF (Verifiable Random Function) Signing and Verifying
- Implemented new random KeyRing generation
- Decoupled Network settings and implemented by interface

