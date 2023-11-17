package pqringctkyber

import (
	"bytes"
	"github.com/cryptosuite/kyber-go/kyber"
	"log"
	"testing"
)

func TestKeyPair(t *testing.T) {
	pp := kyber.Kyber768
	length := 32
	seed := make([]byte, length)
	for i := 0; i < length; i++ {
		seed[i] = byte(i)

	}
	pk, sk, err := KeyPair(pp, seed, length)
	if err != nil {
		log.Fatalf("error in keypair")
	}
	sc, kappa, err := Encaps(pp, pk[:])
	if err != nil {
		log.Fatalf("error in encaps")
	}
	res, err := Decaps(pp, sc, sk)
	if err != nil {
		log.Fatalf("error in decaps")
	}
	if !bytes.Equal(kappa, res) {
		log.Fatalf("error in matched")
	}
}
