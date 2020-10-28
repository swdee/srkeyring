package srwallet

import "testing"

func TestNetSubstrate(t *testing.T) {

	tests := []struct {
		name    string
		net     Network
		version uint8
		prefix  HexPrefix
		netname string
	}{
		{
			name:    "Substrate",
			net:     NetSubstrate{},
			version: 42,
			prefix:  "0x",
			netname: "substrate",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ver := tt.net.Version()
			name := tt.net.Name()
			prefix := tt.net.AddressPrefix()

			if ver != tt.version {
				t.Errorf("Wrong network version, expected %v, got %v", tt.version, ver)
			}

			if prefix != tt.prefix {
				t.Errorf("Wrong address prefix, expected %v, got %v", tt.prefix, prefix)
			}

			if name != tt.netname {
				t.Errorf("Wrong network name, expected %v, got %v", tt.netname, name)
			}
		})
	}
}
