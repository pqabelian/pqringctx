package pqringctx

import (
	"crypto/hmac"
	"fmt"
	"golang.org/x/crypto/sha3"
)

const MACKeyBytesLen = 64
const MACOutputBytesLen = 64

// MACGen
// TODO A Test Implementation
func MACGen(key []byte, message []byte) (messageMac []byte, err error) {
	// todo
	if len(key) != MACKeyBytesLen {
		return nil, fmt.Errorf("MACGen: the input key has an invalid length (%d)", len(key))
	}
	mac := hmac.New(sha3.New512, key)
	mac.Write(message)
	messageMac = mac.Sum(nil)
	return messageMac, nil
}

func MACVerify(key []byte, message []byte, messageMac []byte) error {
	if len(key) != MACKeyBytesLen {
		return fmt.Errorf("MACVerify: the input key has an invalid length (%d)", len(key))
	}

	if len(messageMac) != MACOutputBytesLen {
		return fmt.Errorf("MACVerify: the input messageMac has an invalid length (%d)", len(messageMac))
	}

	computedTag, err := MACGen(key, message)
	if err != nil {
		return fmt.Errorf("MACVerify: error happens when computing mac: %v", err)
	}

	if hmac.Equal(computedTag, messageMac) {
		return nil
	}

	return fmt.Errorf("MACVerify: the input message and messageMac does not match")
}
