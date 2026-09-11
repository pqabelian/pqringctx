package pqringctx

import (
	"bytes"
	"crypto/sha3"
	"errors"
	"fmt"
)

func (pp *PublicParameter) MessageSignatureSign(message []byte, cryptoSpendSecretKey []byte) (*MessageSignature, error) {
	//	Sanity-checks 	begin
	if len(message) == 0 {
		return nil, fmt.Errorf("MessageSignatureSign: the input message is nil/empty")
	}

	// H( H(msg||nonce) || nonce_reverse）
	nonce := RandomBytes(64)
	contentDigest1 := sha3.Sum512(append(message, nonce...))
	nonceReverse := make([]byte, len(nonce))
	for i := 0; i < len(nonce); i++ {
		nonceReverse[i] = nonce[len(nonce)-1-i]
	}
	contentDigest2 := sha3.Sum512(append(contentDigest1[:], nonceReverse...))

	coinSpendSecretKey := cryptoSpendSecretKey[5:]
	apkForSingle, askSp, err := pp.coinSpendSecretKeyForPKHSingleParse(coinSpendSecretKey)
	if err != nil {
		return nil, err
	}
	askSp_ntt := pp.NTTPolyAVec(askSp.s)

	simpleSig, err := pp.simpleSignatureSign(apkForSingle.t, contentDigest2[:], askSp_ntt)
	if err != nil {
		return nil, err
	}

	messageSig := &MessageSignature{
		simpleSig: simpleSig,
		apk:       apkForSingle,
		nonce:     nonce,
	}

	return messageSig, nil
}

// simpleSignatureVerify verifies SimpleSignatureMLP.
// reviewed on 2023.12.18
// refactored on 2024.01.07, using err == nil or not to denote valid or invalid
// todo: multi-round review
// refactored and reviewed by Alice, 2024.07.02
func (pp *PublicParameter) MessageSignatureVerify(message []byte, sig *MessageSignature) error {
	//	Sanity-checks 	begin
	if len(message) == 0 {
		return fmt.Errorf("MessageSignatureVerify: the input message is nil/empty")
	}

	// H( H(msg||nonce) || nonce_reverse）
	nonce := sig.nonce
	contentDigest1 := sha3.Sum512(append(message, nonce...))
	nonceReverse := make([]byte, len(nonce))
	for i := 0; i < len(nonce); i++ {
		nonceReverse[i] = nonce[len(nonce)-1-i]
	}
	contentDigest2 := sha3.Sum512(append(contentDigest1[:], nonceReverse...))

	return pp.simpleSignatureVerify(sig.apk.t, contentDigest2[:], sig.simpleSig)
}

type MessageSignature struct {
	simpleSig *SimpleSignatureMLP
	apk       *AddressPublicKeyForSingle
	nonce     []byte
}

func (pp *PublicParameter) MessageSignatureMatch(sig *MessageSignature, coinAddress []byte) error {
	if sig == nil || len(coinAddress) == 0 {
		return fmt.Errorf("MessageSignatureMatch: the input signature or coinAddress is nil/empty")
	}

	apkHashInAddress := make([]byte, HashOutputBytesLen)
	copy(apkHashInAddress, coinAddress[1:1+HashOutputBytesLen])

	serializedApk, err := pp.serializeAddressPublicKeyForSingle(sig.apk)
	if err != nil {
		return err
	}

	apkHash, err := Hash(serializedApk)
	if err != nil {
		return err
	}

	if bytes.Compare(apkHashInAddress, apkHash) != 0 {
		return errors.New("MessageSignatureMatch: the input signature and address does not match")
	}

	return nil
}

func (pp *PublicParameter) SerializeMessageSignature(sig *MessageSignature) ([]byte, error) {
	if sig == nil {
		return nil, fmt.Errorf("SerializeMessageSignature: signature is nil")
	}

	serializedSig, err := pp.serializeSimpleSignature(sig.simpleSig)
	if err != nil {
		return nil, err
	}

	serializedApk, err := pp.serializeAddressPublicKeyForSingle(sig.apk)
	if err != nil {
		return nil, err
	}
	w := make([]byte, 0, len(serializedSig)+len(serializedApk)+len(sig.nonce))
	w = append(w, serializedSig...)
	w = append(w, serializedApk...)
	w = append(w, sig.nonce...)
	return w, nil
}
func (pp *PublicParameter) DeserializeMessageSignature(serializedMessageSignature []byte) (*MessageSignature, error) {
	if len(serializedMessageSignature) == 0 {
		return nil, fmt.Errorf("DeserializeMessageSignature: the input serializedMessageSignature is nil/empty")
	}

	simpleSigSize := pp.simpleSignatureSerializeSize()
	if len(serializedMessageSignature) < simpleSigSize {
		return nil, fmt.Errorf("DeserializeMessageSignature: the input serializedMessageSignature is too short")
	}
	simpleSig, err := pp.deserializeSimpleSignature(serializedMessageSignature[:simpleSigSize])
	if err != nil {
		return nil, err
	}

	apkSize := pp.addressPublicKeyForSingleSerializeSize()
	if len(serializedMessageSignature) < simpleSigSize+apkSize {
		return nil, fmt.Errorf("DeserializeMessageSignature: the input serializedMessageSignature is too short")
	}
	apk, err := pp.deserializeAddressPublicKeyForSingle(serializedMessageSignature[simpleSigSize:])
	if err != nil {
		return nil, err
	}
	nonce := serializedMessageSignature[simpleSigSize+apkSize:]
	if len(nonce) != 64 {
		return nil, fmt.Errorf("DeserializeMessageSignature: the input serializedMessageSignature is invalid")
	}
	return &MessageSignature{
		simpleSig: simpleSig,
		apk:       apk,
		nonce:     nonce,
	}, nil
}
