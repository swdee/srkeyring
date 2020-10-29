package srwallet

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// HexPrefix defines a prefix used in the hex encoded output
type HexPrefix string

// DecodeHex decodes the hex string to bytes and truncates any prefix used
func DecodeHex(str string, prefix HexPrefix) (seed []byte, ok bool) {

	if strings.HasPrefix(str, string(prefix)) {
		str = strings.TrimPrefix(str, string(prefix))
	}

	res, err := hex.DecodeString(str)
	return res, err == nil
}

// EncodeHex encodes the raw bytes into a hex encoded string and appends any
// prefix required
func EncodeHex(raw []byte, prefix HexPrefix) string {
	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(raw))
}
