package srwallet

import (
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

func TestCompactUInt(t *testing.T) {

	// test vectors taken from
	// https://github.com/Joystream/parity-codec-go/blob/07755503ecfdcb06c73d0e08ceec05b795ef76e5/withreflect/codec_test.go#L146
	tests := map[uint64]string{
		0:              "00",
		63:             "fc",
		64:             "01 01",
		16383:          "fd ff",
		16384:          "02 00 01 00",
		1073741823:     "fe ff ff ff",
		1073741824:     "03 00 00 00 40",
		1<<32 - 1:      "03 ff ff ff ff",
		1 << 32:        "07 00 00 00 00 01",
		1 << 40:        "0b 00 00 00 00 00 01",
		1 << 48:        "0f 00 00 00 00 00 00 01",
		1<<56 - 1:      "0f ff ff ff ff ff ff ff",
		1 << 56:        "13 00 00 00 00 00 00 00 01",
		math.MaxUint64: "13 ff ff ff ff ff ff ff ff",
	}

	for val, expectedHex := range tests {
		res, err := compactUint(val)

		if err != nil {
			t.Fatalf("Error compating Uint: %v", err)
		}

		// strip spaces from expected hex
		cmpHex := strings.ReplaceAll(expectedHex, " ", "")

		resHex := hex.EncodeToString(res)

		if resHex != cmpHex {
			t.Errorf("Failed to compact, expected %v, got %v", cmpHex, resHex)
		}
	}
}
