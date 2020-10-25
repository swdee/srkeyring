package srwallet

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/blake2b"

	"github.com/decred/base58"
)



// ChecksumType represents the one or more checksum types.
//More here: https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
// TODO(ved): Maybe we can add these types to the known list ?
type ChecksumType int

const (
	ss58Prefix = "SS58PRE"

	// SS58Checksum uses the concat(address-type, address) as blake2b hash pre-image
	SS58Checksum ChecksumType = iota
	// AccountIDChecksum uses the address as the blake2b hash pre-image
	AccountID
)



// SS58Address derives ss58 address from the address, network, and checksumType
func SS58Address(addr [32]byte, net Network, ctype ChecksumType) (string, error) {
	version, err := GetNetworkVersion(net)
	if err != nil {
		return "", err
	}

	return sS58AddressWithVersion(addr, version, ctype)
}

// SS58Address derives ss58 address from the address, network version, and checksumType
func sS58AddressWithVersion(addr [32]byte, version uint8, ctype ChecksumType) (string, error) {
	var cbuf []byte
	switch ctype {
	case SS58Checksum:
		cbuf = append([]byte{version}, addr[:]...)
	case AccountID:
		cbuf = addr[:]
	default:
		return "", fmt.Errorf("unknown checksum type: %v", ctype)
	}

	cs, err := ss58Checksum(append(cbuf))
	if err != nil {
		return "", err
	}

	fb := append([]byte{version}, addr[:]...)
	fb = append(fb, cs[0:2]...)
	return base58.Encode(fb), nil
}


// https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
func ss58Checksum(data []byte) ([]byte, error) {
	hasher, err := blake2b.New(64, nil)
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write([]byte(ss58Prefix))
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

// DecodeSS58AddressWithVersion takes a string and checks if it is a validly
// encoded SS58 address and returns the raw address in bytes
func DecodeSS58AddressWithVersion(addr string, net Network, ctype ChecksumType) ([32]byte, error) {
	var rawAddr [32]byte

	// validate network version
	version, err := GetNetworkVersion(net)

	if err != nil {
		return rawAddr, err
	}

	versionBytes := []byte{version}
	versionLen := len(versionBytes)

	//decode address from base58 to raw bytes
	dec := base58.Decode(addr)

	// check that the decoded bytes length is at least the length of the 32 bytes
	// for the raw address plus the network version bytes
	if len(dec) < (versionLen + 32) {
		return rawAddr, fmt.Errorf("invalid string, too short")
	}

	// check the prefix of the decoded bytes is equal to the version
	if !bytes.Equal(versionBytes, dec[:len(versionBytes)]) {
		return rawAddr, fmt.Errorf("invalid network version on decode")
	}

	// get the raw bytes address and remaining bytes as checksum
	bufAddr := dec[versionLen:(32 + versionLen)]
	checksum := dec[(32 + versionLen):]

	var cbuf []byte

	switch ctype {
	case SS58Checksum:
		cbuf = append([]byte{version}, bufAddr[:]...)
	case AccountID:
		cbuf = bufAddr[:]
	default:
		return rawAddr, fmt.Errorf("unknown checksum type: %v", ctype)
	}

	// generate the expected checksum from raw address
	cs, err := ss58Checksum(cbuf)

	if err != nil {
		return rawAddr, err
	}

	// compare checksums
	if !bytes.Equal(checksum, cs[0:2]) {
		return rawAddr, fmt.Errorf("invalid checksum comparison")
	}

	// copy and return valid raw address
	copy(rawAddr[:], bufAddr[:32])

	return rawAddr, nil
}
