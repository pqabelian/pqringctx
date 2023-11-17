package pqringctkem

import (
	"bytes"
	"errors"
	"github.com/cryptosuite/kyber-go/kyber"
	"github.com/cryptosuite/pqringct/pqringctkem/pqringctOQSKem"
	"github.com/cryptosuite/pqringct/pqringctkem/pqringctkyber"
	"log"
)

// KyberKem is the public parameter for kem
var KyberKem = NewParamKem(KEM_OQS_KYBER, nil, "Kyber768")

type VersionKEM uint32

const (
	KEM_KYBER VersionKEM = iota
	KEM_OQS_KYBER
)

type ParamKem struct {
	Version  VersionKEM
	Kyber    *kyber.ParameterSet
	OQSKyber string
}

type ValuePublicKey struct {
	Version      VersionKEM
	SerializedPK []byte
}

type ValueSecretKey struct {
	Version      VersionKEM
	SerializedSK []byte
}

func KeyGen(ppkem *ParamKem, seed []byte, seedLen int) ([]byte, []byte, error) {
	var originSerializedPK, originSerializedSK []byte
	var err error
	switch ppkem.Version {
	case KEM_KYBER:
		originSerializedPK, originSerializedSK, err = pqringctkyber.KeyPair(ppkem.Kyber, seed, seedLen)
		if err != nil {
			return nil, nil, err
		}
	case KEM_OQS_KYBER:
		var recovery bool
		if seed == nil || seedLen < 32 {
			// allocate the space of seed is to match the cgo in  pqringctOQSKem.KeyPair()
			seed = make([]byte, 32)
			recovery = false
		} else {
			recovery = true
		}
		originSerializedPK, originSerializedSK, err = pqringctOQSKem.KeyPair(ppkem.OQSKyber, seed, recovery)
		if err != nil {
			return nil, nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}
	retSerializedPK := make([]byte, 0, 4+len(originSerializedPK))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>0))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>8))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>16))
	retSerializedPK = append(retSerializedPK, byte(ppkem.Version>>24))
	retSerializedPK = append(retSerializedPK, originSerializedPK...)

	retSerializedSK := make([]byte, 0, 4+len(originSerializedSK))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>0))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>8))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>16))
	retSerializedSK = append(retSerializedSK, byte(ppkem.Version>>24))
	retSerializedSK = append(retSerializedSK, originSerializedSK...)

	return retSerializedPK, retSerializedSK, nil
}

func VerifyKeyPair(ppkem *ParamKem, serializedPK []byte, serializedSK []byte) (valid bool, hints string) {
	// check the version
	pkVersion := uint32(serializedPK[0]) << 0
	pkVersion |= uint32(serializedPK[1]) << 8
	pkVersion |= uint32(serializedPK[2]) << 16
	pkVersion |= uint32(serializedPK[3]) << 24

	skVersion := uint32(serializedSK[0]) << 0
	skVersion |= uint32(serializedSK[1]) << 8
	skVersion |= uint32(serializedSK[2]) << 16
	skVersion |= uint32(serializedSK[3]) << 24
	if VersionKEM(pkVersion) != ppkem.Version {
		return false, "the version is not matched"
	}
	if VersionKEM(skVersion) != ppkem.Version {
		return false, "the version is not matched"
	}

	ctKemSerialized, kappa, err := Encaps(ppkem, serializedPK)
	if err != nil {
		return false, err.Error()
	}
	decapsedKappa, err := Decaps(ppkem, ctKemSerialized, serializedSK)
	if err != nil {
		return false, err.Error()
	}
	if !bytes.Equal(kappa, decapsedKappa) {
		return false, "the key pair is not matched"
	}

	return true, ""
}

func Encaps(ppkem *ParamKem, pk []byte) ([]byte, []byte, error) {
	var serializedC, kappa []byte
	var err error
	version := uint32(pk[0]) << 0
	version |= uint32(pk[1]) << 8
	version |= uint32(pk[2]) << 16
	version |= uint32(pk[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, nil, errors.New("the version of kem is not matched")
	}
	switch ppkem.Version {
	case KEM_KYBER:
		serializedC, kappa, err = pqringctkyber.Encaps(ppkem.Kyber, pk[4:])
		if err != nil {
			return nil, nil, err
		}
	case KEM_OQS_KYBER:
		serializedC, kappa, err = pqringctOQSKem.Encaps(ppkem.OQSKyber, pk[4:])
		if err != nil {
			return nil, nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}

	retSerializedC := make([]byte, 0, 4+len(serializedC))

	retSerializedC = append(retSerializedC, byte(ppkem.Version>>0))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>8))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>16))
	retSerializedC = append(retSerializedC, byte(ppkem.Version>>24))
	retSerializedC = append(retSerializedC, serializedC...)

	return retSerializedC, kappa, nil
}

func Decaps(ppkem *ParamKem, serializedC []byte, sk []byte) ([]byte, error) {
	version := uint32(sk[0]) << 0
	version |= uint32(sk[1]) << 8
	version |= uint32(sk[2]) << 16
	version |= uint32(sk[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, errors.New("the version of kem is not matched")
	}
	version = uint32(serializedC[0]) << 0
	version |= uint32(serializedC[1]) << 8
	version |= uint32(serializedC[2]) << 16
	version |= uint32(serializedC[3]) << 24
	if VersionKEM(version) != ppkem.Version {
		return nil, errors.New("the version of kem is not matched")
	}
	var kappa []byte
	var err error
	switch ppkem.Version {
	case KEM_KYBER:
		kappa, err = pqringctkyber.Decaps(ppkem.Kyber, serializedC[4:], sk[4:])
		if err != nil {
			return nil, err
		}
	case KEM_OQS_KYBER:
		kappa, err = pqringctOQSKem.Decaps(ppkem.OQSKyber, serializedC[4:], sk[4:])
		if err != nil {
			return nil, err
		}
	default:
		log.Fatalln("Unsupported KEM version.")
	}
	return kappa, nil
}

func GetKemCiphertextBytesLen(ppkem *ParamKem) int {
	switch ppkem.Version {
	case KEM_KYBER:
		return 4 + ppkem.Kyber.CryptoCiphertextBytes()
	case KEM_OQS_KYBER:
		return 4 + 1088 // k*320 + 128 (k==3) = 3 * 320 + 128 = 960 + 128 = 1088
	default:
		log.Fatalln("Unsupported KEM version.")
	}
	return 0
}

func NewParamKem(version VersionKEM, kyber *kyber.ParameterSet, oqsKEM string) *ParamKem {
	switch version {
	case KEM_KYBER:
		return &ParamKem{
			Version: version,
			Kyber:   kyber,
		}
	default:
		return nil
	}
}
