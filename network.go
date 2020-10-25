package srwallet

import "errors"

// Network is the string name of the network
type Network string

const (
	// Network is the network version to use
	NetSubstrate Network = "substrate"
)

var (
	// ErrUnknownNetwork error when network is not a known network
	ErrUnknownNetwork = errors.New("Unknown Network")
)

// GetNetworkVersion takes a string network name and returns the version number
func GetNetworkVersion(net Network) (uint8, error) {

	kns := map[Network]uint8{
		"substrate": 42,
		"polkadot":  0,
		"kusama":    2,
		"dothereum": 20,
		"kulupu":    16,
		"edgeware":  7,
	}

	version, ok := kns[net]

	if !ok {
		return 0, ErrUnknownNetwork
	}

	return version, nil
}

// AddressPrefix returns the HexPrefix for the given Network
func (n Network) AddressPrefix() HexPrefix {
	switch n {
	case NetSubstrate:
		return SubstratePrefix

	default:
		return NoPrefix
	}
}
