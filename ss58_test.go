package srkeyring

import (
	"reflect"
	"testing"
)

var ss58tests = []struct {
	name  string
	addr  string
	net   Network
	ctype ChecksumType
	ss58  string
}{
	{
		name:  "Address 1",
		addr:  "0x6a0b8913b41eb405f7e2461e014acfdf0e1ee756e127ea6b446e2e4501e7df17",
		net:   NetSubstrate{},
		ctype: SS58Checksum,
		ss58:  "5ETkMpEd5Af7d3aMBpwNVv8sRa4Y1aRBvNSfycZq1ekWPGrN",
	},
	{
		name:  "Address 2",
		addr:  "0xf0ac9f380078d01605c538f67de4d9b14cab7bc50897e0377fccbbce277d4f40",
		net:   NetSubstrate{},
		ctype: SS58Checksum,
		ss58:  "5HWGdRwMFAfm89MChot9sdfaSkpJciStmD4CMfqQHCNLHQqV",
	},
}

func TestSS58Address(t *testing.T) {

	for _, tt := range ss58tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawAddr, ok := DecodeHex(tt.addr, tt.net.AddressPrefix())

			if !ok {
				t.Fatalf("Invalid hex encoded address: %v", tt.addr)
			}

			var rawB [32]byte
			copy(rawB[:], rawAddr)

			res, err := SS58Address(rawB, tt.net, tt.ctype)

			if err != nil {
				t.Fatalf("Error getting SS58 Address: %v", err)
			}

			if res != tt.ss58 {
				t.Errorf("Invalid SS58 Address, expected %v, got %v", tt.ss58, res)
			}
		})
	}
}

func TestDecodeSS58Address(t *testing.T) {

	for _, tt := range ss58tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			//t.Parallel()

			// convert address into bytes
			rawAddr, ok := DecodeHex(tt.addr, tt.net.AddressPrefix())

			if !ok {
				t.Fatalf("Invalid hex encoded address: %v", tt.addr)
			}

			var expectedB [32]byte
			copy(expectedB[:], rawAddr)

			res, err := DecodeSS58Address(tt.ss58, tt.net, tt.ctype)

			if err != nil {
				t.Fatalf("Error decoding SS58 Address: %v", err)
			}

			if !reflect.DeepEqual(res, expectedB) {
				t.Errorf("Invalid SS58 Address decode, expected %v, got %v", expectedB, res)
			}
		})
	}
}
