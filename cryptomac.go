package pqringctx

import (
	"bytes"
	"crypto/hmac"
	"golang.org/x/crypto/sha3"
)

const MACKeyBytesLen = 64
const MACOutputBytesLen = 64

// MACGen
// TODO A Test Implementation
func MACGen(key []byte, message []byte) (messageMac []byte) {
	// todo
	mac := hmac.New(sha3.New512, key)
	mac.Write(message)
	messageMac = mac.Sum(nil)
	return messageMac
}

func MACVerify(key []byte, message []byte, messageMac []byte) bool {
	if bytes.Equal(MACGen(key, message), messageMac) {
		return true
	}
	return false
}
