# srkeyring

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
go get -u https://github.com/swdee/srkeyring
```

## Example

Create KeyRing (Private and Public keys) from Secret URI, output public SS58
address, and sign message.  Verification of signature is performed from KeyRing
generated from public SS58 formatted address.

Note: Error handling is ignored for brevity.

```go
package main

import (
    "github.com/swdee/srkeyring"  
    "log"    
)

func main() {
    // generate keyring from 12 word mnemonic
    secretURI := "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral"
    kr, _ := srkeyring.FromURI(secretURI, srkeyring.NetSubstrate)

    // output public SS58 formatted address
    ss58, _ := kr.SS58Address()  
    log.Printf("SS58 Address: %s", ss58)

    // sign message
    msg := []byte("setec astronomy")
    sig, _ := kr.Sign(kr.SigningContext(msg))
        
    // create new keyring from SS58 public address to verify message signature
    verkr, _ := srkeyring.FromURI(ss58, srkeyring.NetSubstrate)
    
    if !verkr.Verify(verkr.SigningContext(msg), sig) {
        log.Fatalf("Error invalid signature for message")
    } else {
        log.Print("Signature is valid!")
    }
}
```

A more complex example consisting of multiple
parties who create a root KeyRing from which Hard and Soft keys are
derived to setup a controller child KeyRing with granchild public payment 
addresses for a website ecommerce site is shown in test code *TODO LINK*.  

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



