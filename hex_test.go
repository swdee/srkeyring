package srwallet

import (
	"bytes"
	"testing"
)

var hexTests = []struct {
	name   string
	hex    string
	bytes  []byte
	valid  bool
	prefix HexPrefix
}{
	{
		name:   "With Substrate Prefix 1",
		hex:    "0xb69355deefa7a8f33e9297f5af22e680f03597a99d4f4b1c44be47e7a2275802",
		bytes:  []byte{0xb6, 0x93, 0x55, 0xde, 0xef, 0xa7, 0xa8, 0xf3, 0x3e, 0x92, 0x97, 0xf5, 0xaf, 0x22, 0xe6, 0x80, 0xf0, 0x35, 0x97, 0xa9, 0x9d, 0x4f, 0x4b, 0x1c, 0x44, 0xbe, 0x47, 0xe7, 0xa2, 0x27, 0x58, 0x2},
		valid:  true,
		prefix: SubstratePrefix,
	},
	{
		name:   "With No Prefix",
		hex:    "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
		bytes:  []byte{0x46, 0xeb, 0xdd, 0xef, 0x8c, 0xd9, 0xbb, 0x16, 0x7d, 0xc3, 0x8, 0x78, 0xd7, 0x11, 0x3b, 0x7e, 0x16, 0x8e, 0x6f, 0x6, 0x46, 0xbe, 0xff, 0xd7, 0x7d, 0x69, 0xd3, 0x9b, 0xad, 0x76, 0xb4, 0x7a},
		valid:  true,
		prefix: NoPrefix,
	},
	{
		name:   "With Substrate Prefix 2",
		hex:    "0x46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a",
		bytes:  []byte{0x46, 0xeb, 0xdd, 0xef, 0x8c, 0xd9, 0xbb, 0x16, 0x7d, 0xc3, 0x8, 0x78, 0xd7, 0x11, 0x3b, 0x7e, 0x16, 0x8e, 0x6f, 0x6, 0x46, 0xbe, 0xff, 0xd7, 0x7d, 0x69, 0xd3, 0x9b, 0xad, 0x76, 0xb4, 0x7a},
		valid:  true,
		prefix: SubstratePrefix,
	},
	{
		name:   "Invalid Hex",
		hex:    "invalidhex",
		bytes:  []byte{},
		valid:  false,
		prefix: SubstratePrefix,
	},
}

func TestDecodeHex(t *testing.T) {

	for _, tt := range hexTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, valid := DecodeHex(tt.hex, tt.prefix)

			if valid != tt.valid {
				t.Fatalf("Unexpected result for %s, expected %v result", tt.hex, tt.valid)
			}

			if !bytes.Equal(tt.bytes, res) {
				t.Errorf("Resulting hex decode invalid, got %v, wanted %v", res, tt.bytes)
			}
		})
	}
}

func TestEncodeHex(t *testing.T) {

	for _, tt := range hexTests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			res := EncodeHex(tt.bytes, tt.prefix)

			if tt.hex != res && tt.valid {
				t.Errorf("Resulting hex encode invalid, got %v, wanted %v", res, tt.hex)
			}
		})
	}
}
