package pqringctx

import (
	"crypto/hmac"
	"fmt"
	"github.com/cryptosuite/pqringctx/internal"
)

const (
	MACKeyBytesLen    = 64
	MACOutputBytesLen = 64
)
const domainSeparationCustomizationString = "PQRINGCT"

// MACGen
// TODO review the implementation of underlying KMAC
// todo: review, by 2024.06
func MACGen(key []byte, message []byte) (messageMac []byte, err error) {
	if len(key) != MACKeyBytesLen {
		return nil, fmt.Errorf("MACGen: the input key has an invalid length (%d)", len(key))
	}
	kmac256 := internal.NewKMAC256(key, MACOutputBytesLen, []byte(domainSeparationCustomizationString))
	kmac256.Write(message)
	return kmac256.Sum(nil), nil
}

// MACVerify checks the validity of the input message and messageMac, using the input key.
// Note: err != nil implies unexpected cases happens, it is necessary for the caller to print the error to log and/or return err to its caller.
// todo: review, by 2024.06
func MACVerify(key []byte, message []byte, messageMac []byte) (bool, error) {
	if len(key) != MACKeyBytesLen {
		return false, fmt.Errorf("MACVerify: the input key has an invalid length (%d)", len(key))
	}

	if len(messageMac) != MACOutputBytesLen {
		return false, fmt.Errorf("MACVerify: the input messageMac has an invalid length (%d)", len(messageMac))
	}

	computedTag, err := MACGen(key, message)
	if err != nil {
		return false, fmt.Errorf("MACVerify: error happens when computing mac: %v", err)
	}

	// TODO replace with subtle.ConstantTimeCompare()
	if hmac.Equal(computedTag, messageMac) {
		return true, nil
	}

	return false, nil
}
