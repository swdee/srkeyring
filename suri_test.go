package srwallet

import (
	"reflect"
	"testing"
)

func TestPathParts(t *testing.T) {

	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "Path Hard",
			path:     "//joe//polkadot//0",
			expected: []string{"/joe", "/polkadot", "/0"},
		},
		{
			name:     "Path Soft",
			path:     "/joe/polkadot/0",
			expected: []string{"joe", "polkadot", "0"},
		},
		{
			name:     "Path Mixed",
			path:     "//joe/account/1",
			expected: []string{"/joe", "account", "1"},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suri := &SecretURI{
				Path: tt.path,
			}

			parts := suri.pathParts()

			if !reflect.DeepEqual(parts, tt.expected) {
				t.Errorf("Error decoding path into parts, expected %v, got %v", tt.expected, parts)
			}
		})
	}
}

func TestGetJunctions(t *testing.T) {

	tests := []struct {
		name     string
		path     string
		expected []*junction
	}{
		{
			name: "Path Hard",
			path: "//joe//polkadot//0",
			expected: []*junction{
				{
					path:      "joe",
					chainCode: [32]byte{12, 106, 111, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      true,
				},
				{
					path:      "polkadot",
					chainCode: [32]byte{32, 112, 111, 108, 107, 97, 100, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      true,
				},
				{
					path:      "0",
					chainCode: [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      true,
				},
			},
		},
		{
			name: "Path Soft",
			path: "/joe/polkadot/0",
			expected: []*junction{
				{
					path:      "joe",
					chainCode: [32]byte{12, 106, 111, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      false,
				},
				{
					path:      "polkadot",
					chainCode: [32]byte{32, 112, 111, 108, 107, 97, 100, 111, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      false,
				},
				{
					path:      "0",
					chainCode: [32]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      false,
				},
			},
		},
		{
			name: "Path Mixed",
			path: "//joe/account/1",
			expected: []*junction{
				{
					path:      "joe",
					chainCode: [32]byte{12, 106, 111, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      true,
				},
				{
					path:      "account",
					chainCode: [32]byte{28, 97, 99, 99, 111, 117, 110, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      false,
				},
				{
					path:      "1",
					chainCode: [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					hard:      false,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suri := &SecretURI{
				Path: tt.path,
			}

			jun, err := suri.GetJunctions()

			if err != nil {
				t.Fatalf("Error getting junctions: %v", err)
			}

			if !reflect.DeepEqual(jun, tt.expected) {
				t.Errorf("Invalid junctions, expected %v, got %v", tt.expected, jun)
			}
		})
	}
}

func TestNewSecretURI(t *testing.T) {

	tests := []struct {
		name     string
		suri     string
		net      Network
		expected *SecretURI
		valid    bool
	}{
		{
			name: "Mnemonic",
			suri: "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
				Path:     "",
				Password: "",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name: "Mnemonic with Path",
			suri: "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral/john/account/1",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
				Path:     "/john/account/1",
				Password: "",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name: "Mnemonic with Password",
			suri: "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral///pass1234",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
				Path:     "",
				Password: "pass1234",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name: "Mnemonic with Path and Password",
			suri: "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral/john/account/1///pass1234",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "zebra extra skill occur rose muscle reveal robust cigar tilt jungle coral",
				Path:     "/john/account/1",
				Password: "pass1234",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name: "Secret Hex with Path and Password",
			suri: "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7/william/merchant/4///pass1234",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "0x7202a4eba69bb283e8e9a3f5f6f0fc64bb02e6d20fb4b6bde13caec148f2cca7",
				Path:     "/william/merchant/4",
				Password: "pass1234",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name: "SS58 Address with Path",
			suri: "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3/william/merchant/4",
			net:  NetSubstrate{},
			expected: &SecretURI{
				Phrase:   "5FA3hDvvp85LEijvPpZZ2eEUvwpxhzy9PCSe6jLiboUx2kA3",
				Path:     "/william/merchant/4",
				Password: "",
				Network:  NetSubstrate{},
			},
			valid: true,
		},
		{
			name:     "Invalid SURI",
			suri:     "",
			net:      NetSubstrate{},
			expected: nil,
			valid:    false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			suri, err := NewSecretURI(tt.suri, tt.net)

			if err != nil {
				if !tt.valid {
					// error was expected
					return
				}

				t.Fatalf("Error getting SURI: %v", err)
			}

			if !reflect.DeepEqual(suri, tt.expected) {
				t.Errorf("Invalid SURI, expected %v, got %v", tt.expected, suri)
			}
		})
	}
}
