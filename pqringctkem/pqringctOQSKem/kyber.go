package pqringctOQSKem

import (
	"github.com/cryptosuite/liboqs-go/oqs"
)

const (
	OQSKYBER768 = "Kyber768"
)

// KeyPair generate the key pair and it provide key recovery function
// The seed must be allocated regardless of whether the recovery flag is set or not
// The seed length is at least 32.
func KeyPair(kemName string, seed []byte, recovery bool) ([]byte, []byte, error) {
	var instance oqs.KeyEncapsulation
	defer instance.Clean()
	var err error
	var pk, sk []byte
	err = instance.Init(kemName, nil)
	if err != nil {
		return nil, nil, err
	}
	pk, err = instance.GenerateKeyPairWithRecovery(seed, recovery)
	if err != nil {
		return nil, nil, err
	}
	skT := instance.ExportSecretKey()
	sk = make([]byte, len(skT))
	copy(sk, skT)
	return pk, sk, nil
}

func Encaps(kemName string, pk []byte) ([]byte, []byte, error) {
	var instance oqs.KeyEncapsulation
	defer instance.Clean()
	var err error
	err = instance.Init(kemName, nil)
	if err != nil {
		return nil, nil, err
	}
	return instance.EncapSecret(pk)
}

func Decaps(kemName string, cipher []byte, sk []byte) ([]byte, error) {
	var instance oqs.KeyEncapsulation
	defer instance.Clean()
	var err error
	err = instance.Init(kemName, sk)
	if err != nil {
		return nil, err
	}
	return instance.DecapSecret(cipher)
}
