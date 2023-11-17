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
