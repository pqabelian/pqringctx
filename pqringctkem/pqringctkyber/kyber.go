package pqringctkyber

import (
	"crypto/rand"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"golang.org/x/crypto/sha3"
	"log"
)

// RandomBytes returns a byte array with given length from crypto/rand.Reader
func RandomBytes(length int) []byte {
	res := make([]byte, 0, length)
	for length > 0 {
		tmp := make([]byte, length)
		n, err := rand.Read(tmp)
		if err != nil {
			log.Fatalln(err)
			return nil
		}
		res = append(res, tmp[:n]...)
		length -= n
	}
	return res
}

func KeyPair(kpp *kyber.ParameterSet, seed []byte, seedLen int) ([]byte, []byte, error) {
	// check the validity of the length of seed
	if seed == nil || len(seed) != seedLen {
		return nil, nil, errors.New("the length of seed is invalid")
	}
	if seed == nil {
		seed = RandomBytes(seedLen)
	}

	// this temporary byte slice is for protect seed unmodified
	// hash(seed) to meet the length required by kyber
	usedSeed := make([]byte, 2*seedLen)
	shake256 := sha3.NewShake256()
	shake256.Write(seed)
	shake256.Read(usedSeed)
	return kyber.KeyPair(kpp, usedSeed)
}
func Encaps(kpp *kyber.ParameterSet, pk []byte) ([]byte, []byte, error) {
	return kyber.Encaps(kpp, pk)
}
func Decaps(kpp *kyber.ParameterSet, cipher []byte, sk []byte) ([]byte, error) {
	got := kyber.Decaps(kpp, sk, cipher)
	if got == nil {
		return nil, errors.New("kyber.Decaps err")
	}
	return got, nil
}
func GetKemCiphertextBytesLen(kpp *kyber.ParameterSet) int {
	return kpp.CryptoCiphertextBytes()
}
