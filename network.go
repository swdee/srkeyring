package srkeyring

// Network defines the interface for a specific networks settings to be used
// for key generation and address formatting
type Network interface {
	// Name returns the network name used in the KeyRing SigningContext transcript
	Name() string
	// Version returns the network version number used in SS58 address formatting
	// see https://github.com/paritytech/substrate/wiki/External-Address-Format-(SS58)#checksum-types
	// section Address Type
	Version() uint8
	// AddressPrefix returns a prefix to apply to hex encoded addresses for
	// public key and private seed
	AddressPrefix() HexPrefix
	// ChecksumStart is the starting byte position of the blake2d checksum
	// calculated when generating the SS58 address checksum.  Valid ranges
	// are 0 to 30.  Standard value is 0.
	ChecksumStart() int
	// ChecksumEnd is the end byte position of the blake2d checksum
	// calculated when generating the SS58 address checksum.  Valid ranges
	// are 2 to 32, where ChecksumEnd must be a higher number than
	// ChecksumStart.  Standard value is 2.
	ChecksumEnd() int
}

// force Substrate to implement Network interface
var _ Network = &NetSubstrate{}

// NetSubstrate implements the Network interface to define Substrates mainnet
// settings
type NetSubstrate struct{}

// Name returns the network name used in the KeyRing SigningContext transcript
func (n NetSubstrate) Name() string {
	return "substrate"
}

// Version returns the network version number used in SS58 address formatting
func (n NetSubstrate) Version() uint8 {
	return 42
}

// AddressPrefix returns a prefix to apply to hex encoded addresses for
// public key and private seed
func (n NetSubstrate) AddressPrefix() HexPrefix {
	return "0x"
}

// ChecksumStart is the starting byte position of the blake2d checksum
// calculated when generating the SS58 address checksum
func (n NetSubstrate) ChecksumStart() int {
	return 0
}

// ChecksumEnd is the end byte position of the blake2d checksum
// calculated when generating the SS58 address checksum
func (n NetSubstrate) ChecksumEnd() int {
	return 2
}
