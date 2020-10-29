package srkeyring

import (
	"encoding/binary"
	"golang.org/x/crypto/blake2b"
	"strconv"
	"strings"
)

const junctionIDLen = 32

// junction contains the chaincode for the given path part from a Secret and
// if its a Soft or Hard key junction
type junction struct {
	// path is a single part of the Secret URI path
	path string
	// chainCode of the path part
	chainCode [32]byte
	// hard is a flag to indicate if hard or soft key
	hard bool
}

// newJunction takes a part of the path and parses it into a junction
func newJunction(part string) (*junction, error) {

	j := &junction{}

	if strings.HasPrefix(part, "/") {
		// hard key
		j.hard = true
		part = strings.TrimPrefix(part, "/")
	}

	var bc []byte
	u64, err := strconv.ParseUint(part, 10, 0)

	if err == nil {
		bc = make([]byte, 8)
		binary.LittleEndian.PutUint64(bc, u64)

	} else {
		// compactUint is parities codec for data serialization used for storing
		// the length of the "part" of a UTF-8 string which allocates 4 bytes
		// per character.  In ascii the word "joe" converts to 3*4 = 12 or
		// "polkadot" is 8*4 = 32.
		cl, err := compactUint(uint64(len(part)))

		if err != nil {
			return nil, err
		}

		bc = append(cl, part...)

	}

	if len(bc) > junctionIDLen {
		// if the serialized "part" is longer than 32 bytes then use its hash
		b := blake2b.Sum256(bc)
		bc = b[:]
	}

	copy(j.chainCode[:len(bc)], bc)
	j.path = part

	return j, nil
}
