package pqringctxkem

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/cryptosuite/kyber-go/kyber"
	"github.com/pqabelian/pqringctx/pqringctxkem/pqringctOQSKem"
	"testing"
)

func TestNewParamKem(t *testing.T) {
	type args struct {
		version VersionKEM
		kyber   *kyber.ParameterSet
		oqsKEM  string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Kyber-go",
			args: args{
				version: KEM_KYBER,
				kyber:   kyber.Kyber768,
				oqsKEM:  "",
			},
		},
		{
			name: "OQSKyber",
			args: args{
				version: KEM_OQS_KYBER,
				kyber:   nil,
				oqsKEM:  pqringctOQSKem.OQSKYBER768,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paramKem := NewParamKem(tt.args.version, tt.args.kyber, tt.args.oqsKEM)
			seed := make([]byte, 32)
			rand.Read(seed)

			serialziedPK, serialziedSK, err := KeyGen(paramKem, seed, 32)
			if err != nil {
				t.Fatalf("error in keypair")
			}
			fmt.Println(seed)

			copiedSerializedSK := make([]byte, len(serialziedSK))
			copy(copiedSerializedSK[:], serialziedSK)
			valid, hints := VerifyKeyPair(paramKem, serialziedPK, copiedSerializedSK)
			if !valid {
				t.Fatalf("invalid keypair %v", hints)
			}

			sc, kappa, err := Encaps(paramKem, serialziedPK)
			if err != nil {
				t.Fatalf("error in encaps")
			}
			res, err := Decaps(paramKem, sc, serialziedSK)
			if err != nil {
				t.Fatalf("error in decaps")
			}
			if !bytes.Equal(kappa, res) {
				t.Fatalf("error in matched")
			}

			lengthPublicKey := GetKemPublicKeyBytesLen(paramKem)
			lengthSecretKey := GetKemSecretKeyBytesLen(paramKem)
			lengthCiphertext := GetKemCiphertextBytesLen(paramKem)
			lengthSharedSecret := GetKemSharedSecretBytesLen(paramKem)
			fmt.Println("LengthPublicKey = ", lengthPublicKey)
			fmt.Println("LengthSecretKey = ", lengthSecretKey)
			fmt.Println("LengthCiphertext = ", lengthCiphertext)
			fmt.Println("LengthSharedSecret = ", lengthSharedSecret)

		})
	}
}
