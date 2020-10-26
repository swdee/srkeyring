package srwallet

import "testing"

func TestGetNetworkVersion(t *testing.T) {

	tests := []struct {
		name     string
		net      Network
		expected uint8
		valid    bool
	}{
		{
			name:     "Substrate",
			net:      NetSubstrate,
			expected: 42,
			valid:    true,
		},
		{
			name:     "Invalid Network",
			net:      "TheForce",
			expected: 0,
			valid:    false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res, err := GetNetworkVersion(tt.net)

			if err != nil && tt.valid {
				t.Fatalf("Error getting Network version: %v", err)
			}

			if res != tt.expected && err == nil {
				t.Errorf("Wrong network version, expected %v, got %v", tt.expected, res)
			}
		})
	}
}

func TestAddressPrefix(t *testing.T) {

	tests := []struct {
		name     string
		net      Network
		expected HexPrefix
	}{
		{
			name:     "Substrate",
			net:      NetSubstrate,
			expected: SubstratePrefix,
		},
		{
			name:     "Invalid Network",
			net:      Network("NetInvalid"),
			expected: NoPrefix,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := tt.net.AddressPrefix()

			if res != tt.expected {
				t.Errorf("Invalid address prefix, expected %v, got %v", tt.expected, res)
			}
		})
	}
}
