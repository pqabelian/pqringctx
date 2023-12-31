package pqringctOQSKem

import (
	"bytes"
	"fmt"
	"testing"
)

func TestKeyPair_Encaps_Decaps(t *testing.T) {
	pp := OQSKYBER768
	seed := make([]byte, 32)
	pk, sk, err := KeyPair(pp, seed, false)
	if err != nil {
		t.Fatalf("error in keypair")
	}
	fmt.Println(seed)
	sc, kappa, err := Encaps(pp, pk)
	if err != nil {
		t.Fatalf("error in encaps")
	}
	res, err := Decaps(pp, sc, sk)
	if err != nil {
		t.Fatalf("error in decaps")
	}
	if !bytes.Equal(kappa, res) {
		t.Fatalf("error in matched")
	}
}

func TestKeyPair_Size(t *testing.T) {
	pp := OQSKYBER768
	lengthPublicKey, err := LengthPublicKey(pp)
	if err != nil {
		panic(err)
	}
	lengthSecretKey, err := LengthSecretKey(pp)
	if err != nil {
		panic(err)
	}
	lengthCiphertext, err := LengthCiphertext(pp)
	if err != nil {
		panic(err)
	}
	lengthSharedSecret, err := LengthSharedSecret(pp)
	if err != nil {
		panic(err)
	}
	fmt.Println("LengthPublicKey = ", lengthPublicKey)
	fmt.Println("LengthSecretKey = ", lengthSecretKey)
	fmt.Println("LengthCiphertext = ", lengthCiphertext)
	fmt.Println("LengthSharedSecret = ", lengthSharedSecret)
}
