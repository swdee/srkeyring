package srwallet

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// compactUint writes an unsigned integer to a byte slice using parties compact
// encoding based on the implementation at
// https://github.com/Joystream/parity-codec-go/blob/07755503ecfdcb06c73d0e08ceec05b795ef76e5/withreflect/codec.go#L69
func compactUint(v uint64) ([]byte, error) {
	var buf bytes.Buffer

	if v < 1<<30 {
		if v < 1<<6 {
			return []byte{byte(v) << 2}, nil

		} else if v < 1<<14 {
			err := binary.Write(&buf, binary.LittleEndian, uint16(v<<2)+1)

			if err != nil {
				return nil, err
			}

		} else {
			err := binary.Write(&buf, binary.LittleEndian, uint32(v<<2)+2)

			if err != nil {
				return nil, err
			}
		}

		return buf.Bytes(), nil
	}

	n := byte(0)
	limit := uint64(1 << 32)

	for v >= limit && limit > 256 { // when overflows, limit will be < 256
		n++
		limit <<= 8
	}

	if n > 4 {
		return nil, errors.New("assertion error: n>4 needed to compact-encode uint64")
	}

	err := buf.WriteByte((n << 2) + 3)

	if err != nil {
		return nil, err
	}

	b := make([]byte, 8)

	binary.LittleEndian.PutUint64(b, v)
	_, err = buf.Write(b[:4+n])

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
