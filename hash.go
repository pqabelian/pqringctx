package pqringct

import "golang.org/x/crypto/sha3"

const HashOutputBytesLen = 64

// Hash encapsulates a hash function to output a byte stream of arbitrary length
// TODO_DONE: Should be as a parameter not a function,in that way, it can be substituted by other function.
// this function can be changed by other hash function than sha3.NewShake256
func Hash(data []byte) ([]byte, error) {
	res := sha3.Sum512(data)
	return res[:], nil
}
