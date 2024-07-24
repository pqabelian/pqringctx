package pqringctx

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/pqabelian/pqringctx/pqringctxkem"
)

// AddressSecretKeySp namely SpendKey.
// reviewed by Alice, 2024.06.23
type AddressSecretKeySp struct {
	//	s \in (S_{\gamma_a})^{L_a}, where \gamma_a is small, say 2 at this moment.
	//	As s has infinity normal in [-2, 2], here we define s as PolyAVec, rather than PolyANTTVec.
	s *PolyAVec
}

// AddressSecretKeySn namely SerialNumberKey.
// reviewed by Alice, 2024.06.23
type AddressSecretKeySn struct {
	ma *PolyANTT
}

// AddressPublicKeyForRing is the struct for full-privacy Address which is used in pair with AddressSecretKeyForRing.
// reviewed by Alice, 2024.06.23
type AddressPublicKeyForRing struct {
	t *PolyANTTVec // directly in NTT form, length K_a
	e *PolyANTT
}

// AddressSecretKeyForRing is the struct for full-privacy Secret Key which is used in pair with AddressPublicKeyForRing.
// reviewed by Alice, 2024.06.23
type AddressSecretKeyForRing struct {
	*AddressSecretKeySp
	*AddressSecretKeySn
}

// AddressPublicKeyForSingle is the struct for pseudonym-privacy Address which is used in pair with AddressSecretKeyForSingle.
// Comparing with AddressPublicKeyForRing, this address does not include parts related to protecting privacy.
// reviewed by Alice, 2024.06.23
type AddressPublicKeyForSingle struct {
	t *PolyANTTVec // directly in NTT form, length K_a
}

// AddressSecretKeyForSingle is the struct for pseudonym-privacy secret key which is used in pair with AddressPublicKeyForSingle.
// reviewed by Alice, 2024.06.23
type AddressSecretKeyForSingle struct {
	*AddressSecretKeySp
}

// CoinAddressKeyForPKRingGen generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.05
// reviewed on 2023.12.30
// REVIEWED ON 2023/12/31
// reviewed by Alice, 2024.06.23
func (pp *PublicParameter) CoinAddressKeyForPKRingGen(coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte,
	coinDetectorKey []byte, publicRand []byte) (coinAddress []byte, coinSpendSecretKey []byte,
	coinSerialNumberSecretKey []byte, err error) {

	if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
		return nil, nil, nil, fmt.Errorf("CoinAddressKeyForPKRingGen: the input coinDetectorKey's length (%d) is incorrect", len(coinDetectorKey))
	}

	if len(publicRand) != pp.GetParamKeyGenPublicRandBytesLen() {
		return nil, nil, nil, fmt.Errorf("CoinAddressKeyForPKRingGen: the input publicRand's length (%d) is incorrect", len(publicRand))
	}

	apk, ask, err := pp.addressKeyForRingGen(coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedAPK, err := pp.serializeAddressPublicKeyForRing(apk)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedASKSp, err := pp.serializeAddressSecretKeySp(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, nil, err
	}
	serializedASKSn, err := pp.serializeAddressSecretKeySn(ask.AddressSecretKeySn)
	if err != nil {
		return nil, nil, nil, err
	}

	coinAddress = make([]byte, 1+len(serializedAPK)+len(publicRand)+pp.GetParamMACOutputBytesLen())
	coinAddress[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinAddress[1:], serializedAPK)
	copy(coinAddress[1+len(serializedAPK):], publicRand)
	coinAddressMsg := make([]byte, 1+len(serializedAPK)+len(publicRand))
	copy(coinAddressMsg, coinAddress[:1+len(serializedAPK)+len(publicRand)])
	tag, err := MACGen(coinDetectorKey, coinAddressMsg)
	if err != nil {
		return nil, nil, nil, err
	}
	copy(coinAddress[1+len(serializedAPK)+len(publicRand):], tag)

	coinSpendSecretKey = make([]byte, 1+len(serializedASKSp))
	coinSpendSecretKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSpendSecretKey[1:], serializedASKSp)

	coinSerialNumberSecretKey = make([]byte, 1+len(serializedASKSn))
	coinSerialNumberSecretKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSerialNumberSecretKey[1:], serializedASKSn)

	return coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, nil

	//return nil, nil, nil, err
}

// CoinAddressKeyForPKRingGenSerialNumberKeyPart generates coinSerialNumberSecretKey from the input coinSerialNumberKeyRandSeed.
// NOTE: As a part of CoinAddressKeyForPKRingGen, the codes must be consistent with that in CoinAddressKeyForPKRingGen.
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) CoinAddressKeyForPKRingGenSerialNumberKeyPart(coinSerialNumberKeyRandSeed []byte) (coinSerialNumberSecretKey []byte, err error) {

	askSn, err := pp.addressKeyForRingGenSerialNumberKeyPart(coinSerialNumberKeyRandSeed)
	if err != nil {
		return nil, err
	}

	serializedASKSn, err := pp.serializeAddressSecretKeySn(askSn)
	if err != nil {
		return nil, err
	}

	coinSerialNumberSecretKey = make([]byte, 1+len(serializedASKSn))
	coinSerialNumberSecretKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSerialNumberSecretKey[1:], serializedASKSn)

	return coinSerialNumberSecretKey, nil

	//return nil, nil, nil, err
}

// CoinAddressKeyForPKRingVerify verifies whether the input (coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey) is valid,
// i.e., was honestly generated by CoinAddressKeyForPKRingGen.
// added on 2023.12.13
// reviewed on 2023.12.14
// reviewed on 2023.12.30
// REVIEWED ON 2023/12/31
// todo: reviewed by Alice, 2024.06.23
// reviewed by Ocean
func (pp *PublicParameter) CoinAddressKeyForPKRingVerify(coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte, coinDetectorKey []byte) (bool, error) {

	//	not nil
	if len(coinAddress) == 0 || len(coinSpendSecretKey) == 0 || len(coinSerialNumberSecretKey) == 0 {
		return false, nil
	}

	//	address and keys shall have the same coinAddressType
	coinAddressTypeInAddress, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return false, err
	}

	coinAddressTypeInKey, err := pp.ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey)
	if err != nil {
		return false, err
	}
	if coinAddressTypeInKey != coinAddressTypeInAddress {
		return false, nil
	}

	coinAddressTypeInKey, err = pp.ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(coinSerialNumberSecretKey)
	if err != nil {
		return false, err
	}
	if coinAddressTypeInKey != coinAddressTypeInAddress {
		return false, nil
	}

	//	match check
	if coinAddressTypeInAddress != CoinAddressTypePublicKeyForRingPre && coinAddressTypeInAddress != CoinAddressTypePublicKeyForRing {
		return false, fmt.Errorf("CoinAddressKeyForPKRingVerify: the coinAddressType of the input (coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey) is not CoinAddressTypePublicKeyForRingPre or CoinAddressTypePublicKeyForRing")
	}

	var apk *AddressPublicKeyForRing
	var askSp *AddressSecretKeySp
	var askSn *AddressSecretKeySn

	if coinAddressTypeInAddress == CoinAddressTypePublicKeyForRingPre {
		// 	the address and keys were generated by pqringct.CoinAddressKeyGen (with pqringct)
		//	This is to achieve the back-compatibility with the address and keys that were generated by pqringct.

		//	Note that the following codes are BASED ON the following FACTS:
		//	(1) pqringctx.PublicParameter is the same as pqringct.PublicParameter, i.e.,
		//	the caller initialized the two parameters using the same input.
		//	(2) CoinAddressKeyForPKRingGen in pqringctx is the same as AddressKeyGen in pqringct, except
		//	 (a) the coinAddressType is explicitly prefixed, and
		//   (b) rename the AddressPubicKey to coinAddress, AddressSecretKeySp to coinSpendSecretKey, and AddressSecretKeySn to coinSerialNumberSecretKey.

		//	check the size
		if len(coinAddress) != pp.addressPublicKeyForRingSerializeSize() {
			return false, nil
		}
		if len(coinSpendSecretKey) != pp.addressSecretKeySpSerializeSize() {
			return false, nil
		}
		if len(coinSerialNumberSecretKey) != pp.addressSecretKeySnSerializeSize() {
			return false, nil
		}

		//	parse to Address and Keys for Ring
		apk, err = pp.deserializeAddressPublicKeyForRing(coinAddress)
		if err != nil {
			return false, err
		}
		askSp, err = pp.deserializeAddressSecretKeySp(coinSpendSecretKey)
		if err != nil {
			return false, err
		}
		askSn, err = pp.deserializeAddressSecretKeySn(coinSerialNumberSecretKey)
		if err != nil {
			return false, err
		}
	} else if coinAddressTypeInAddress == CoinAddressTypePublicKeyForRing {
		// 	the address and keys were generated by CoinAddressKeyForPKRingGen

		//	check the size
		apkSize := pp.addressPublicKeyForRingSerializeSize()
		publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
		detectorTagSize := pp.GetParamMACOutputBytesLen()
		if len(coinAddress) != 1+apkSize+publicRandSize+detectorTagSize {
			return false, nil
		}
		if len(coinSpendSecretKey) != 1+pp.addressSecretKeySpSerializeSize() {
			return false, nil
		}
		if len(coinSerialNumberSecretKey) != 1+pp.addressSecretKeySnSerializeSize() {
			return false, nil
		}
		if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
			return false, fmt.Errorf("CoinAddressKeyForPKRingVerify: the input coinDetectorKey has an invalid length (%d)", len(coinDetectorKey))
		}

		//	check the MAC tag
		coinAddressMsg := make([]byte, 1+apkSize+publicRandSize)
		coinAddressTag := make([]byte, detectorTagSize)
		copy(coinAddressMsg, coinAddress[:1+apkSize+publicRandSize])
		copy(coinAddressTag, coinAddress[1+apkSize+publicRandSize:])
		valid, err := MACVerify(coinDetectorKey, coinAddressMsg, coinAddressTag)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}

		//	parse to Address and Keys for Ring
		apk, err = pp.deserializeAddressPublicKeyForRing(coinAddress[1 : 1+pp.addressPublicKeyForRingSerializeSize()])
		if err != nil {
			return false, err
		}
		askSp, err = pp.deserializeAddressSecretKeySp(coinSpendSecretKey[1:])
		if err != nil {
			return false, err
		}
		askSn, err = pp.deserializeAddressSecretKeySn(coinSerialNumberSecretKey[1:])
		if err != nil {
			return false, err
		}
	}

	ask := &AddressSecretKeyForRing{
		AddressSecretKeySp: askSp,
		AddressSecretKeySn: askSn,
	}
	valid, hints := pp.addressKeyForRingVerify(apk, ask)
	if valid {
		return true, nil
	}
	return false, fmt.Errorf(hints)
}

// CoinAddressForPKRingDetect checks whether the input coinAddress contains a valid (message, mac) pair with respect the input coinDetectorKey.
// Note that err != nil implies that unexpected cases (such as incorrect call) happen,
// and it is necessary for the caller to print the error to log and/or return the error to its caller.
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) CoinAddressForPKRingDetect(coinAddress []byte, coinDetectorKey []byte) (bool, error) {

	//	not nil
	if len(coinAddress) == 0 {
		return false, fmt.Errorf("CoinAddressForPKRingDetect: the input coinAddress is nil/empty")
	}

	if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
		return false, fmt.Errorf("CoinAddressForPKRingDetect: the input coinDetectorKey has an invalid length (%d)", len(coinDetectorKey))
	}

	//	address and keys shall have the same coinAddressType
	coinAddressTypeInAddress, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return false, err
	}

	//	match check
	if coinAddressTypeInAddress != CoinAddressTypePublicKeyForRing {
		return false, fmt.Errorf("CoinAddressForPKRingDetect: the coinAddressType of the input coinAddress is not CoinAddressTypePublicKeyForRing")
	}

	//	check the size
	apkSize := pp.addressPublicKeyForRingSerializeSize()
	publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
	detectorTagSize := pp.GetParamMACOutputBytesLen()
	if len(coinAddress) != 1+apkSize+publicRandSize+detectorTagSize {
		return false, nil
	}

	//	check the MAC tag
	coinAddressMsg := make([]byte, 1+apkSize+publicRandSize)
	coinAddressTag := make([]byte, detectorTagSize)
	copy(coinAddressMsg, coinAddress[:1+apkSize+publicRandSize])
	copy(coinAddressTag, coinAddress[1+apkSize+publicRandSize:])
	valid, err := MACVerify(coinDetectorKey, coinAddressMsg, coinAddressTag)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}

	return true, nil

}

// CoinAddressKeyForPKHSingleGen generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy,
// where the CoinAddress will be a hash, and used in a single manner.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.05
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// REVIEWED ON 2023/12/31
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) CoinAddressKeyForPKHSingleGen(coinSpendKeyRandSeed []byte, coinDetectorKey []byte, publicRand []byte) (coinAddress []byte, coinSpendSecretKey []byte, err error) {

	if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
		return nil, nil, fmt.Errorf("CoinAddressKeyForPKHSingleGen: the input coinDetectorKey's length(%d) is incorrect", len(coinDetectorKey))
	}
	if len(publicRand) != pp.GetParamKeyGenPublicRandBytesLen() {
		return nil, nil, fmt.Errorf("CoinAddressKeyForPKHSingleGen: the input publicRand's length(%d) is incorrect", len(publicRand))
	}

	apk, ask, err := pp.addressKeyForSingleGen(coinSpendKeyRandSeed)
	if err != nil {
		return nil, nil, err
	}

	serializedAPK, err := pp.serializeAddressPublicKeyForSingle(apk)
	if err != nil {
		return nil, nil, err
	}

	serializedASKSp, err := pp.serializeAddressSecretKeySp(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, err
	}

	apkHash, err := Hash(serializedAPK)
	if err != nil {
		return nil, nil, err
	}
	coinAddress = make([]byte, 1+HashOutputBytesLen+len(publicRand)+pp.GetParamMACOutputBytesLen())
	coinAddress[0] = byte(CoinAddressTypePublicKeyHashForSingle)
	copy(coinAddress[1:], apkHash)
	copy(coinAddress[1+HashOutputBytesLen:], publicRand)
	coinAddressMsg := make([]byte, 1+HashOutputBytesLen+len(publicRand))
	copy(coinAddressMsg, coinAddress[:1+HashOutputBytesLen+len(publicRand)])
	tag, err := MACGen(coinDetectorKey, coinAddressMsg)
	if err != nil {
		return nil, nil, err
	}
	copy(coinAddress[1+HashOutputBytesLen+len(publicRand):], tag)

	coinSpendSecretKey = make([]byte, 1+len(serializedAPK)+len(serializedASKSp))
	coinSpendSecretKey[0] = byte(CoinAddressTypePublicKeyHashForSingle)
	copy(coinSpendSecretKey[1:], serializedAPK)
	copy(coinSpendSecretKey[1+len(serializedAPK):], serializedASKSp)

	return coinAddress, coinSpendSecretKey, nil

	//	return nil, nil, err
}

// CoinAddressKeyForPKHSingleVerify verifies whether the input (coinAddress, coinSpendSecretKey) is valid,
// i.e., was honestly generated by CoinAddressKeyForPKHSingleGen.
// added on 2023.12.13
// reviewed on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) CoinAddressKeyForPKHSingleVerify(coinAddress []byte, coinSpendSecretKey []byte, coinDetectorKey []byte) (bool, error) {

	//	not nil
	if len(coinAddress) == 0 || len(coinSpendSecretKey) == 0 {
		return false, fmt.Errorf("CoinAddressKeyForPKHSingleVerify: the input coinAddress or coinSpendSecretKey is nil/empty")
	}

	//	address and keys shall have the same coinAddressType
	coinAddressTypeInAddress, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return false, err
	}

	coinAddressTypeInKey, err := pp.ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey)
	if err != nil {
		return false, err
	}
	if coinAddressTypeInKey != coinAddressTypeInAddress {
		return false, nil
	}

	//	match check
	if coinAddressTypeInAddress != CoinAddressTypePublicKeyHashForSingle {
		return false, fmt.Errorf("CoinAddressKeyForPKHSingleVerify: the coinAddressType of the input (coinAddress, coinSpendSecretKey) is not CoinAddressTypePublicKeyHashForSingle")
	}
	// 	the address and keys were generated by CoinAddressKeyForPKHSingleGen

	//	check the size
	publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
	detectorTagSize := pp.GetParamMACOutputBytesLen()

	if len(coinAddress) != 1+HashOutputBytesLen+publicRandSize+detectorTagSize {
		return false, nil
	}

	apkLen := pp.addressPublicKeyForSingleSerializeSize()
	askSpLen := pp.addressSecretKeySpSerializeSize()

	if len(coinSpendSecretKey) != 1+apkLen+askSpLen {
		return false, nil
	}

	if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
		return false, fmt.Errorf("CoinAddressKeyForPKHSingleVerify: the input coinDetectorKey has an invalid length (%d)", len(coinDetectorKey))
	}

	//	check the tag
	coinAddressMsg := make([]byte, 1+HashOutputBytesLen+publicRandSize)
	coinAddressTag := make([]byte, detectorTagSize)
	copy(coinAddressMsg, coinAddress[:1+HashOutputBytesLen+publicRandSize])
	copy(coinAddressTag, coinAddress[1+HashOutputBytesLen+publicRandSize:])
	valid, err := MACVerify(coinDetectorKey, coinAddressMsg, coinAddressTag)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}

	//	parse to Address and Keys for Single
	apkHashInAddress := make([]byte, HashOutputBytesLen)
	copy(apkHashInAddress, coinAddress[1:1+HashOutputBytesLen])

	serializedApk := make([]byte, apkLen)
	copy(serializedApk, coinSpendSecretKey[1:1+apkLen])

	serializedAskSp := make([]byte, askSpLen)
	copy(serializedAskSp, coinSpendSecretKey[1+apkLen:])

	//	check hash of apk
	apkHash, err := Hash(serializedApk)
	if err != nil {
		return false, err
	}
	if bytes.Compare(apkHashInAddress, apkHash) != 0 {
		return false, nil
	}

	//	deserialize to apk and ask for single
	var apk *AddressPublicKeyForSingle
	var askSp *AddressSecretKeySp
	apk, err = pp.deserializeAddressPublicKeyForSingle(serializedApk)
	if err != nil {
		return false, err
	}
	askSp, err = pp.deserializeAddressSecretKeySp(serializedAskSp)
	if err != nil {
		return false, err
	}

	ask := &AddressSecretKeyForSingle{
		AddressSecretKeySp: askSp,
	}

	valid, hints := pp.addressKeyForSingleVerify(apk, ask)
	if valid {
		return true, nil
	} else {

	}

	return false, fmt.Errorf(hints)
}

// CoinAddressForPKHSingleDetect checks whether the input coinAddress contains a valid (message, mac) pair with respect the input coinDetectorKey.
// Note that err != nil implies that unexpected cases (such as incorrect call) happen,
// and it is necessary for the caller to print the error to log and/or return the error to its caller.
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) CoinAddressForPKHSingleDetect(coinAddress []byte, coinDetectorKey []byte) (bool, error) {

	//	not nil
	if len(coinAddress) == 0 {
		return false, fmt.Errorf("CoinAddressForPKHSingleDetect: the input coinAddress is nil/empty")
	}

	if len(coinDetectorKey) != pp.GetParamMACKeyBytesLen() {
		return false, fmt.Errorf("CoinAddressForPKHSingleDetect: the input coinDetectorKey has an invalid length (%d)", len(coinDetectorKey))
	}

	//	address and keys shall have the same coinAddressType
	coinAddressTypeInAddress, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return false, err
	}

	//	match check
	if coinAddressTypeInAddress != CoinAddressTypePublicKeyHashForSingle {
		return false, fmt.Errorf("CoinAddressForPKHSingleDetect: the coinAddressType of the input coinAddress is not CoinAddressTypePublicKeyHashForSingle")
	}
	// 	the address was generated by CoinAddressKeyForPKHSingleGen

	//	check the size
	publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
	detectorTagSize := pp.GetParamMACOutputBytesLen()

	if len(coinAddress) != 1+HashOutputBytesLen+publicRandSize+detectorTagSize {
		return false, nil
	}

	//	check the tag
	coinAddressMsg := make([]byte, 1+HashOutputBytesLen+publicRandSize)
	coinAddressTag := make([]byte, detectorTagSize)
	copy(coinAddressMsg, coinAddress[:1+HashOutputBytesLen+publicRandSize])
	copy(coinAddressTag, coinAddress[1+HashOutputBytesLen+publicRandSize:])
	valid, err := MACVerify(coinDetectorKey, coinAddressMsg, coinAddressTag)
	if err != nil {
		return false, err
	}
	if !valid {
		return false, nil
	}

	return true, nil
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in TxoMLP.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
// reviewed on 2023.12.07
// todo: review by 2024.06
// reviewed by ocean
func (pp *PublicParameter) CoinValueKeyGen(randSeed []byte) (coinValuePublicKey []byte, coinValueSecretKey []byte, err error) {
	return pqringctxkem.KeyGen(pp.paramKem, randSeed, pp.paramKeyGenSeedBytesLen)
}

// CoinValueKeyVerify verifies whether the input (coinValuePublicKey []byte, coinValueSecretKey []byte) is valid.
// Note that the current implementation is BASED ON the following FACT/ASSUMPTION:
// pqringctxkem.VerifyKeyPair with pp.paramKem is the same as, is back-compatible with pqringctkem.VerifyKeyPair with pp.paramKem.
// added on 2023.12.13
// todo: review
// todo: confirm the back-compatible
// todo: review by 2024.06
// reviewed by Ocean
func (pp *PublicParameter) CoinValueKeyVerify(coinValuePublicKey []byte, coinValueSecretKey []byte) (valid bool, hints string) {
	//	From the caller, (coinValuePublicKey []byte, coinValueSecretKey []byte) was obtained by calling (pp *PublicParameter) CoinValueKeyGen(randSeed []byte) ([]byte, []byte, error)
	return pqringctxkem.VerifyKeyPair(pp.paramKem, coinValuePublicKey, coinValueSecretKey)
}

// ExtractCoinAddressTypeFromCoinAddress extract the CoinAddressType from the input coinAddress.
// reviewed on 2023.12.05
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) ExtractCoinAddressTypeFromCoinAddress(coinAddress []byte) (CoinAddressType, error) {
	n := len(coinAddress)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.addressPublicKeyForRingSerializeSize() {
		return CoinAddressTypePublicKeyForRingPre, nil

	} else if n == 1+pp.addressPublicKeyForRingSerializeSize()+pp.GetParamKeyGenPublicRandBytesLen()+pp.GetParamMACOutputBytesLen() {
		//	should be a coinAddress generated by CoinAddressKeyForPKRingGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyForRing, nil

	} else if n == 1+HashOutputBytesLen+pp.GetParamKeyGenPublicRandBytesLen()+pp.GetParamMACOutputBytesLen() {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyHashForSingle, nil

	}

	return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the input coinAddress has a length that is not supported")
}

// ExtractPublicRandFromCoinAddress extracts the PublicRand from the input coinAddress.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) ExtractPublicRandFromCoinAddress(coinAddress []byte) ([]byte, error) {

	n := len(coinAddress)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.addressPublicKeyForRingSerializeSize() {
		return nil, fmt.Errorf("ExtractPublicRandFromCoinAddress: the input coinAddress's coinAddressType is CoinAddressTypePublicKeyForRingPre")

	} else if n == 1+pp.addressPublicKeyForRingSerializeSize()+pp.GetParamKeyGenPublicRandBytesLen()+pp.GetParamMACOutputBytesLen() {
		//	should be a coinAddress generated by CoinAddressKeyForPKRingGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return nil, fmt.Errorf("ExtractPublicRandFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}

		publicRand := make([]byte, pp.GetParamKeyGenPublicRandBytesLen())
		copy(publicRand, coinAddress[1+pp.addressPublicKeyForRingSerializeSize():1+pp.addressPublicKeyForRingSerializeSize()+pp.GetParamKeyGenPublicRandBytesLen()])
		return publicRand, nil

	} else if n == 1+HashOutputBytesLen+pp.GetParamKeyGenPublicRandBytesLen()+pp.GetParamMACOutputBytesLen() {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("ExtractPublicRandFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}

		publicRand := make([]byte, pp.GetParamKeyGenPublicRandBytesLen())
		copy(publicRand, coinAddress[1+HashOutputBytesLen:1+HashOutputBytesLen+pp.GetParamKeyGenPublicRandBytesLen()])
		return publicRand, nil
	}

	return nil, fmt.Errorf("ExtractPublicRandFromCoinAddress: the input coinAddress has a length that is not supported")
}

// ExtractCoinAddressTypeFromCoinSpendSecretKey extracts coinAddressType from the input coinSpendSecretKey.
// reviewed on 2023.12.12
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey []byte) (CoinAddressType, error) {
	n := len(coinSpendSecretKey)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.addressSecretKeySpSerializeSize() {
		return CoinAddressTypePublicKeyForRingPre, nil

	} else if n == 1+pp.addressSecretKeySpSerializeSize() {
		//	should be a coinAddress generated by AddressKeyForRingGen
		coinAddressType := CoinAddressType(coinSpendSecretKey[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSpendSecretKey: the length of the input coinSpendSecretKey and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyForRing, nil

	} else if n == 1+pp.addressPublicKeyForSingleSerializeSize()+pp.addressSecretKeySpSerializeSize() {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen
		coinAddressType := CoinAddressType(coinSpendSecretKey[0])
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSpendSecretKey: the length of the input coinSpendSecretKey and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyHashForSingle, nil

	}

	return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSpendSecretKey: the input coinSpendSecretKey has a length that is not supported")
}

// ExtractCoinAddressTypeFromCoinSerialNumberSecretKey extracts CoinAddressType from the input CoinSerialNumberSecretKey.
// reviewed on 2023.12.12
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(coinSnSecretKey []byte) (CoinAddressType, error) {
	n := len(coinSnSecretKey)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.addressSecretKeySnSerializeSize() {
		return CoinAddressTypePublicKeyForRingPre, nil

	} else if n == 1+pp.addressSecretKeySnSerializeSize() {
		//	should be a coinAddress generated by AddressKeyForRingGen
		coinAddressType := CoinAddressType(coinSnSecretKey[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSerialNumberSecretKey: the length of the input coinSnSecretKey and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyForRing, nil

	} else if n == 0 {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen, where the coinSnSecretKey is nil
		return CoinAddressTypePublicKeyHashForSingle, nil
	}

	return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSerialNumberSecretKey: the input coinSnSecretKey has a length that is not supported")
}

// GetCoinAddressSize returns the CoinAddress size corresponding to the input CoinAddressType.
// reviewed on 2023.12.05
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) GetCoinAddressSize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressPublicKeyForRingSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressPublicKeyForRingSerializeSize() + pp.GetParamKeyGenPublicRandBytesLen() + pp.GetParamMACOutputBytesLen(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 1 + HashOutputBytesLen + pp.GetParamKeyGenPublicRandBytesLen() + pp.GetParamMACOutputBytesLen(), nil
	default:
		return 0, fmt.Errorf("GetCoinAddressSize: the input coinAddressType (%d) is not supported", coinAddressType)
	}
}

// GetCoinSpendSecretKeySize returns the size of CoinSpendSecretKey, according to the input CoinAddressType.
// reviewed on 2023.12.12
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) GetCoinSpendSecretKeySize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressSecretKeySpSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressSecretKeySpSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 1 + pp.addressPublicKeyForSingleSerializeSize() + pp.addressSecretKeySpSerializeSize(), nil
	default:
		return 0, fmt.Errorf("GetCoinSpendSecretKeySize: the input coinAddressType (%d) is not supported", coinAddressType)
	}
}

// GetCoinSerialNumberSecretKeySize returns the size of CoinSerialNumberSecretKey, according to the input CoinAddressType.
// reviewed on 2023.12.12
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) GetCoinSerialNumberSecretKeySize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressSecretKeySnSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressSecretKeySnSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 0, nil
	default:
		return 0, fmt.Errorf("GetCoinSerialNumberSecretKeySize: the input coinAddressType (%d) is not supported", coinAddressType)
	}
}

// GetCoinValuePublicKeySize returns the CoinValuePublicKey size
// todo: review, by 2024.06
// reviewed by Ocean
func (pp *PublicParameter) GetCoinValuePublicKeySize() int {
	// todo(MPL): 4 + 1184
	return pqringctxkem.GetKemPublicKeyBytesLen(pp.paramKem)
}

// GetCoinValueSecretKeySize
// todo: review, by 2024.06
// reviewed by Ocean
func (pp *PublicParameter) GetCoinValueSecretKeySize() int {
	// todo(MPL): 4 + 2400
	return pqringctxkem.GetKemSecretKeyBytesLen(pp.paramKem)
}

// DetectCoinAddress checks whether the input coinAddress contains a valid (message, mac) pair with respect the input coinDetectorKey.
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) DetectCoinAddress(coinAddress []byte, coinDetectorKey []byte) (bool, error) {
	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinAddress(coinAddress)
	if err != nil {
		return false, err
	}

	switch coinAddressType {
	case CoinAddressTypePublicKeyForRing:
		return pp.CoinAddressForPKRingDetect(coinAddress, coinDetectorKey)

	case CoinAddressTypePublicKeyHashForSingle:
		return pp.CoinAddressForPKHSingleDetect(coinAddress, coinDetectorKey)

	default:
		return false, errors.New("unsupported coin address type")
	}
}

//	CoinAddress and CoinKeys	end

//	helper functions	begin

// addressKeyForRingGen generates (AddressPublicKeyForRing, AddressSecretKeyForRing) from the input seed.
// If the seed is empty, this algorithm is a randomized algorithm.
// If the seed is not empty and has the correct length (which can be obtained by GetParamKeyGenSeedBytesLen() ), it is a deterministic algorithm,
// where all randomness will be derived from the input seed.
// NOTE: The coinSpendKeyRandSeed (resp. coinSerialNumberKeyRandSeed) either is nil or has the correct length (paramKeyGenSeedBytesLen).
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
// todo: erase the memory?
func (pp *PublicParameter) addressKeyForRingGen(coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte) (apk *AddressPublicKeyForRing, ask *AddressSecretKeyForRing, err error) {
	// check the validity of the length of seed
	if coinSpendKeyRandSeed != nil && len(coinSpendKeyRandSeed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, fmt.Errorf("addressKeyForRingGen: the length of coinSpendKeyRandSeed (%d) is invalid", len(coinSpendKeyRandSeed))
	}
	localCoinSpendKeyRandSeed := make([]byte, pp.paramKeyGenSeedBytesLen)
	if coinSpendKeyRandSeed == nil {
		localCoinSpendKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	} else {
		copy(localCoinSpendKeyRandSeed, coinSpendKeyRandSeed)
	}

	if coinSerialNumberKeyRandSeed != nil && len(coinSerialNumberKeyRandSeed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, fmt.Errorf("addressKeyForRingGen: the length of coinSerialNumberKeyRandSeed (%d) is invalid", len(coinSerialNumberKeyRandSeed))
	}
	localCoinSerialNumberKeyRandSeed := make([]byte, pp.paramKeyGenSeedBytesLen)
	if coinSerialNumberKeyRandSeed == nil {
		localCoinSerialNumberKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	} else {
		copy(localCoinSerialNumberKeyRandSeed, coinSerialNumberKeyRandSeed)
	}

	// this temporary byte slice is for protect seed unmodified
	//tmp := make([]byte, pp.paramKeyGenSeedBytesLen)
	//
	//copy(tmp, localCoinSpendKeyRandSeed)
	//s, err := pp.expandAddressSKsp(tmp)
	s, err := pp.expandAddressSKsp(localCoinSpendKeyRandSeed)
	if err != nil {
		return nil, nil, err
	}

	//	copy(tmp, coinSerialNumberKeyRandSeed)
	//ma, err := pp.expandAddressSKsn(tmp)
	ma, err := pp.expandAddressSKsn(localCoinSerialNumberKeyRandSeed)
	if err != nil {
		return nil, nil, err
	}

	// t = A * s, will be as a part of public key
	s_ntt := pp.NTTPolyAVec(s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	// e = <a,s>+ma
	e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ma)

	apk = &AddressPublicKeyForRing{
		t: t,
		e: e,
	}
	ask = &AddressSecretKeyForRing{
		AddressSecretKeySp: &AddressSecretKeySp{s: s},
		AddressSecretKeySn: &AddressSecretKeySn{ma: ma},
	}

	// todo: erase the memory?

	return apk, ask, nil
}

// addressKeyForRingGenSerialNumberKeyPart generates AddressSecretKeySn from the input coinSerialNumberKeyRandSeed.
// NOTE: As a part of addressKeyForRingGen, the codes must be consistent with that in addressKeyForRingGen.
// Note: coinSerialNumberKeyRandSeed either is nil or has the correct length paramKeyGenSeedBytesLen.
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) addressKeyForRingGenSerialNumberKeyPart(coinSerialNumberKeyRandSeed []byte) (askSn *AddressSecretKeySn, err error) {
	// check the validity of the length of seed

	if coinSerialNumberKeyRandSeed != nil && len(coinSerialNumberKeyRandSeed) != pp.paramKeyGenSeedBytesLen {
		return nil, fmt.Errorf("addressKeyForRingGenSerialNumberKeyPart: the length of coinSerialNumberKeyRandSeed (%d) is invalid", len(coinSerialNumberKeyRandSeed))
	}
	localCoinSerialNumberKeyRandSeed := make([]byte, pp.paramKeyGenSeedBytesLen)
	if coinSerialNumberKeyRandSeed == nil {
		localCoinSerialNumberKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	} else {
		copy(localCoinSerialNumberKeyRandSeed, coinSerialNumberKeyRandSeed)
	}

	//// this temporary byte slice is for protect seed unmodified
	////tmp := make([]byte, pp.paramKeyGenSeedBytesLen)
	////
	////copy(tmp, localCoinSpendKeyRandSeed)
	////s, err := pp.expandAddressSKsp(tmp)
	//s, err := pp.expandAddressSKsp(localCoinSpendKeyRandSeed)
	//if err != nil {
	//	return nil, nil, err
	//}

	//	copy(tmp, coinSerialNumberKeyRandSeed)
	//ma, err := pp.expandAddressSKsn(tmp)
	ma, err := pp.expandAddressSKsn(localCoinSerialNumberKeyRandSeed)
	if err != nil {
		return nil, err
	}

	//// t = A * s, will be as a part of public key
	//s_ntt := pp.NTTPolyAVec(s)
	//t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)
	//
	//// e = <a,s>+ma
	//e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ma)
	//
	//apk = &AddressPublicKeyForRing{
	//	t: t,
	//	e: e,
	//}
	//ask = &AddressSecretKeyForRing{
	//	AddressSecretKeySp: &AddressSecretKeySp{s: s},
	//	AddressSecretKeySn: &AddressSecretKeySn{ma: ma},
	//}

	// todo: erase the memory?

	return &AddressSecretKeySn{ma: ma}, nil
}

// addressKeyForRingVerify check whether the input AddressPublicKeyForRing and AddressSecretKeyForRing match.
// reviewed on 2023.12.05.
// reviewed on 2023.12.14
// reviewed by Alice, 2024.06.24
// refactored and reviewed by Alice, 2024.07.01
func (pp *PublicParameter) addressKeyForRingVerify(apk *AddressPublicKeyForRing, ask *AddressSecretKeyForRing) (valid bool, hints string) {

	if !pp.AddressPublicKeyForRingSanityCheck(apk) {
		return false, "addressKeyForRingVerify: the input apk *AddressPublicKeyForRing is not well-form"
	}

	if !pp.AddressSecretKeyForRingSanityCheck(ask) {
		return false, "addressKeyForRingVerify: the input apk *AddressSecretKeyForRing is not well-form"
	}

	// compute t = A * s
	s_ntt := pp.NTTPolyAVec(ask.s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	// compute e = <a,s>+ma
	e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ask.ma)

	// compare computed (t,e) and (apk.t, apk.e)
	if !(pp.PolyANTTVecEqualCheck(t, apk.t) && pp.PolyANTTEqualCheck(e, apk.e)) {
		return false, "addressKeyForRingVerify: the AddressPublicKeyForRing computed from AddressSecretKeyForRing does not match the input one"
	}

	return true, ""
}

// addressKeyForSingleGen generates (AddressPublicKeyForSingle, AddressSecretKeyForSingle) from the input seed.
// If the seed is empty, this algorithm is a randomized algorithm.
// If the seed is not empty and has the correct length (which can be obtained by GetParamKeyGenSeedBytesLen() ), it is a deterministic algorithm,
// where all randomness will be derived from the input seed.
// Note: coinSpendKeyRandSeed either is nil or has the correct length paramKeyGenSeedBytesLen.
// reviewed on 2023.12.05.
// reviewed on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
// todo: erase the memory?
func (pp *PublicParameter) addressKeyForSingleGen(coinSpendKeyRandSeed []byte) (apk *AddressPublicKeyForSingle, ask *AddressSecretKeyForSingle, err error) {
	// check the validity of the length of seed
	if coinSpendKeyRandSeed != nil && len(coinSpendKeyRandSeed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, fmt.Errorf("AddressKeyForSingleGen: the length of coinSpendKeyRandSeed is invalid")
	}
	localCoinSpendKeyRandSeed := make([]byte, pp.paramKeyGenSeedBytesLen)
	if coinSpendKeyRandSeed == nil {
		localCoinSpendKeyRandSeed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	} else {
		copy(localCoinSpendKeyRandSeed, coinSpendKeyRandSeed)
	}

	//// this temporary byte slice is for protect seed unmodified
	//tmp := make([]byte, pp.paramKeyGenSeedBytesLen)
	//
	//copy(tmp, coinSpendKeyRandSeed)
	//s, err := pp.expandAddressSKsp(tmp)

	s, err := pp.expandAddressSKsp(localCoinSpendKeyRandSeed)
	if err != nil {
		return nil, nil, err
	}

	//copy(tmp, seed)
	//ma, err := pp.expandAddressSKsn(tmp)
	//if err != nil {
	//	return nil, nil, err
	//}

	// t = A * s, will be as a part of public key
	s_ntt := pp.NTTPolyAVec(s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	//// e = <a,s>+ma
	//e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ma)

	apk = &AddressPublicKeyForSingle{
		t: t,
		//		e: e,
	}
	ask = &AddressSecretKeyForSingle{
		AddressSecretKeySp: &AddressSecretKeySp{s: s},
		//AddressSecretKeySn: &AddressSecretKeySn{ma: ma},
	}
	return apk, ask, nil
}

// addressKeyForSingleVerify verify whether the input AddressPublicKeyForSingle and AddressSecretKeyForSingle match.
// reviewed on 2023.12.05.
// reviewed on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
// refactored and reviewed by Alice, 2024.07.01
func (pp *PublicParameter) addressKeyForSingleVerify(apk *AddressPublicKeyForSingle, ask *AddressSecretKeyForSingle) (valid bool, hints string) {

	if !pp.AddressPublicKeyForSingleSanityCheck(apk) {
		return false, "addressKeyForSingleVerify: the input apk *AddressPublicKeyForSingle is not well-form"
	}

	if !pp.AddressSecretKeyForSingleSanityCheck(ask) {
		return false, "addressKeyForSingleVerify: the input ask *AddressSecretKeyForSingle is not well-form"
	}

	// compute t = A * s
	s_ntt := pp.NTTPolyAVec(ask.s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	//// compute e = <a,s>+ma
	//e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ask.ma)

	// compare computed (t,e) and (apk.t, apk.e)
	//	if !(pp.PolyANTTVecEqualCheck(t, apk.t) && pp.PolyANTTEqualCheck(e, apk.e)) {
	if !pp.PolyANTTVecEqualCheck(t, apk.t) {
		return false, "addressKeyForSingleVerify: the AddressPublicKeyForSingle computed from AddressSecretKeyForSingle does not match the input one"
	}

	return true, ""
}

// AddressPublicKeyForRingSerializeSize returns the serialized size for AddressPublicKeyForRing.
// review on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed by Alice, 2023.06.24
func (pp *PublicParameter) addressPublicKeyForRingSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t) + pp.PolyANTTSerializeSize()
	return (pp.paramKA + 1) * pp.PolyANTTSerializeSize()
}

// serializeAddressPublicKeyForRing serialize the input AddressPublicKeyForRing to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.25
func (pp *PublicParameter) serializeAddressPublicKeyForRing(apk *AddressPublicKeyForRing) ([]byte, error) {
	var err error

	if !pp.AddressPublicKeyForRingSanityCheck(apk) {
		return nil, fmt.Errorf("serializeAddressPublicKeyForRing: the input AddressPublicKeyForRing is not well-form")
	}

	length := pp.addressPublicKeyForRingSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKA; i++ {
		err = pp.writePolyANTT(w, apk.t.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}
	err = pp.writePolyANTT(w, apk.e)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeAddressPublicKeyForRing deserialize the input []byte to an AddressPublicKeyForRing.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) deserializeAddressPublicKeyForRing(serializedAPKForRing []byte) (*AddressPublicKeyForRing, error) {
	var err error
	r := bytes.NewReader(serializedAPKForRing)

	t := pp.NewPolyANTTVec(pp.paramKA)
	var e *PolyANTT

	for i := 0; i < pp.paramKA; i++ {
		t.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}
	e, err = pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressPublicKeyForRing{t, e}, nil
}

// addressPublicKeyForSingleSerializeSize returns the serialize size for AddressPublicKeyForSingle.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) addressPublicKeyForSingleSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t)
	return pp.paramKA * pp.PolyANTTSerializeSize()
}

// serializeAddressPublicKeyForSingle serialize the input AddressPublicKeyForSingle to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) serializeAddressPublicKeyForSingle(apk *AddressPublicKeyForSingle) ([]byte, error) {
	var err error

	if !pp.AddressPublicKeyForSingleSanityCheck(apk) {
		return nil, fmt.Errorf("serializeAddressPublicKeyForSingle: the input AddressPublicKeyForSingle is not well-form")
	}

	length := pp.addressPublicKeyForSingleSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKA; i++ {
		err = pp.writePolyANTT(w, apk.t.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// deserializeAddressPublicKeyForSingle deserialize the input []byte to an AddressPublicKeyForSingle.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) deserializeAddressPublicKeyForSingle(serializedAPKForSingle []byte) (*AddressPublicKeyForSingle, error) {
	var err error
	r := bytes.NewReader(serializedAPKForSingle)

	t := pp.NewPolyANTTVec(pp.paramKA)

	for i := 0; i < pp.paramKA; i++ {
		t.polyANTTs[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}

	return &AddressPublicKeyForSingle{t}, nil
}

// addressSecretKeySpSerializeSize return the fixed size of AddressSecretKeySp.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) addressSecretKeySpSerializeSize() int {
	// s polyAVec with length L_a, wih
	return pp.paramLA * pp.PolyASerializeSizeGamma()
}

// serializeAddressSecretKeySp serialize the input AddressSecretKeySp to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) serializeAddressSecretKeySp(askSp *AddressSecretKeySp) ([]byte, error) {
	var err error
	if askSp == nil || askSp.s == nil {
		return nil, fmt.Errorf("serializeAddressSecretKeySp: there is nil pointer in AddressSecretKeySp")
	}

	if len(askSp.s.polyAs) != pp.paramLA {
		return nil, fmt.Errorf("serializeAddressSecretKeySp: the format of AddressSecretKeySp does not match the design")
	}
	for i := 0; i < pp.paramLA; i++ {
		if !pp.PolyASanityCheck(askSp.s.polyAs[i]) {
			return nil, fmt.Errorf("serializeAddressSecretKeySp: the input of askSp.s.polyAs[%d] is not well-form", i)
		}

		if askSp.s.polyAs[i].infNorm() > int64(pp.paramGammaA) {
			return nil, fmt.Errorf("serializeAddressSecretKeySp: the input of askSp.s.polyAs[%d]'s normal is not in the allowed scope", i)
		}
	}

	// s is in its poly form and has infinite normal in [-Gamma_a, Gamma_a] where Gamma_a is 2 at this moment,
	// we serialize its poly from.
	askSpLen := pp.addressSecretKeySpSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, askSpLen))
	for i := 0; i < pp.paramLA; i++ {
		err = pp.writePolyAGamma(w, askSp.s.polyAs[i])
		if err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

// deserializeAddressSecretKeySp deserialize the input []byte to an AddressSecretKeySp.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) deserializeAddressSecretKeySp(serializedASKSp []byte) (*AddressSecretKeySp, error) {
	var err error
	r := bytes.NewReader(serializedASKSp)
	s := pp.NewPolyAVec(pp.paramLA)
	for i := 0; i < pp.paramLA; i++ {
		s.polyAs[i], err = pp.readPolyAGamma(r)
		if err != nil {
			return nil, err
		}
	}
	return &AddressSecretKeySp{s}, nil
}

// addressSecretKeySnSerializeSize return the fixed size of AddressSecretKeySn.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) addressSecretKeySnSerializeSize() int {
	return pp.PolyANTTSerializeSize()
}

// serializeAddressSecretKeySn serialize the input AddressSecretKeySn to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) serializeAddressSecretKeySn(askSn *AddressSecretKeySn) ([]byte, error) {
	var err error
	if askSn == nil {
		return nil, errors.New("serializeAddressSecretKeySn: there is nil pointer in AddressSecretKeySn")
	}

	if !pp.PolyANTTSanityCheck(askSn.ma) {
		return nil, errors.New("serializeAddressSecretKeySn: the input AddressSecretKeySn.sa is not well-form")
	}

	snLength := pp.addressSecretKeySnSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, snLength))
	err = pp.writePolyANTT(w, askSn.ma)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// deserializeAddressSecretKeySn deserialize the input []byte to an AddressSecretKeySn.
// reviewed on 2023.12.05.
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) deserializeAddressSecretKeySn(serializedASKSn []byte) (*AddressSecretKeySn, error) {
	r := bytes.NewReader(serializedASKSn)
	ma, err := pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressSecretKeySn{ma}, nil
}

//	CoinAddress and Keys Parse	begin

// coinSpendSecretKeyForPKRingParse parses the input coinSpendSecretKey, which was generated by CoinAddressKeyForPKRingGen or pqringct.CoinAddressKeyGen
// to an AddressSecretKeySp.
// added on 2023.12.14
// reviewed on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) coinSpendSecretKeyForPKRingParse(coinSpendSecretKey []byte) (*AddressSecretKeySp, error) {
	if len(coinSpendSecretKey) == 0 {
		return nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the input coinSpendSecretKey is nil/empty")
	}

	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey)
	if err != nil {
		return nil, err
	}

	serializedASKSpLen := pp.addressSecretKeySpSerializeSize()
	serializedASKSp := make([]byte, serializedASKSpLen)
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		if len(coinSpendSecretKey) != serializedASKSpLen {
			return nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyForRingPre, but has an invalid length %d", len(coinSpendSecretKey))
		}
		copy(serializedASKSp, coinSpendSecretKey[0:])

	case CoinAddressTypePublicKeyForRing:
		if len(coinSpendSecretKey) != 1+serializedASKSpLen {
			return nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyForRing, but has an invalid length %d", len(coinSpendSecretKey))
		}
		copy(serializedASKSp, coinSpendSecretKey[1:])

	case CoinAddressTypePublicKeyHashForSingle:
		return nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyHashForSingle")
	default:
		return nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the coinAddressType of input coinSpendSecretKey is not supported")
	}

	askSp, err := pp.deserializeAddressSecretKeySp(serializedASKSp)
	if err != nil {
		return nil, err
	}

	return askSp, nil
}

// coinSerialNumberSecretKeyForPKRingParse parses the input coinSerialNumberSecretKey, which was generated by CoinAddressKeyForPKRingGen or pqringct.CoinAddressKeyGen
// to an AddressSecretKeySn.
// added on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) coinSerialNumberSecretKeyForPKRingParse(coinSerialNumberSecretKey []byte) (*AddressSecretKeySn, error) {
	if len(coinSerialNumberSecretKey) == 0 {
		return nil, fmt.Errorf("coinSerialNumberSecretKeyForPKRingParse: the input coinSpendSecretKey is nil/empty")
	}

	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(coinSerialNumberSecretKey)
	if err != nil {
		return nil, err
	}

	serializedASKSnLen := pp.addressSecretKeySnSerializeSize()
	serializedASKSn := make([]byte, serializedASKSnLen)
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		if len(coinSerialNumberSecretKey) != serializedASKSnLen {
			return nil, fmt.Errorf("coinSerialNumberSecretKeyForPKRingParse: the coinAddressType of input coinSerialNumberSecretKey is CoinAddressTypePublicKeyForRingPre, but has an invalid length %d", len(coinSerialNumberSecretKey))
		}
		copy(serializedASKSn, coinSerialNumberSecretKey[0:])

	case CoinAddressTypePublicKeyForRing:
		if len(coinSerialNumberSecretKey) != 1+serializedASKSnLen {
			return nil, fmt.Errorf("coinSerialNumberSecretKeyForPKRingParse: the coinAddressType of input coinSerialNumberSecretKey is CoinAddressTypePublicKeyForRing, but has an invalid length %d", len(coinSerialNumberSecretKey))
		}
		copy(serializedASKSn, coinSerialNumberSecretKey[1:])

	case CoinAddressTypePublicKeyHashForSingle:
		return nil, fmt.Errorf("coinSerialNumberSecretKeyForPKRingParse: the coinAddressType of input coinSerialNumberSecretKey is CoinAddressTypePublicKeyHashForSingle")
	default:
		return nil, fmt.Errorf("coinSerialNumberSecretKeyForPKRingParse: the coinAddressType of input coinSerialNumberSecretKey is not supported")
	}

	askSn, err := pp.deserializeAddressSecretKeySn(serializedASKSn)
	if err != nil {
		return nil, err
	}

	return askSn, nil
}

// coinSpendSecretKeyForPKHSingleParse parses the input coinSpendSecretKey, which was generated by CoinAddressKeyForPKHSingleGen or pqringct.CoinAddressKeyGen
// to an AddressSecretKeySp.
// added on 2023.12.14
// reviewed on 2023.12.30
// reviewed by Alice, 2024.06.24
func (pp *PublicParameter) coinSpendSecretKeyForPKHSingleParse(coinSpendSecretKey []byte) (*AddressPublicKeyForSingle, *AddressSecretKeySp, error) {
	if len(coinSpendSecretKey) == 0 {
		return nil, nil, fmt.Errorf("coinSpendSecretKeyForPKHSingleParse: the input coinSpendSecretKey is nil/empty")
	}

	coinAddressType, err := pp.ExtractCoinAddressTypeFromCoinSpendSecretKey(coinSpendSecretKey)
	if err != nil {
		return nil, nil, err
	}

	serializedAPKLen := pp.addressPublicKeyForSingleSerializeSize()
	serializedAPK := make([]byte, serializedAPKLen)
	serializedASKSpLen := pp.addressSecretKeySpSerializeSize()
	serializedASKSp := make([]byte, serializedASKSpLen)

	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return nil, nil, fmt.Errorf("coinSpendSecretKeyForPKHSingleParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyForRingPre")

	case CoinAddressTypePublicKeyForRing:
		return nil, nil, fmt.Errorf("coinSpendSecretKeyForPKHSingleParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyForRingPre")

	case CoinAddressTypePublicKeyHashForSingle:
		if len(coinSpendSecretKey) != 1+serializedAPKLen+serializedASKSpLen {
			return nil, nil, fmt.Errorf("coinSpendSecretKeyForPKHSingleParse: the coinAddressType of input coinSpendSecretKey is CoinAddressTypePublicKeyHashForSingle, but has an invalid length %d", len(coinSpendSecretKey))
		}

		copy(serializedAPK, coinSpendSecretKey[1:1+serializedAPKLen])
		copy(serializedASKSp, coinSpendSecretKey[1+serializedAPKLen:])

	default:
		return nil, nil, fmt.Errorf("coinSpendSecretKeyForPKRingParse: the coinAddressType of input coinSpendSecretKey is not supported")
	}

	apk, err := pp.deserializeAddressPublicKeyForSingle(serializedAPK)
	if err != nil {
		return nil, nil, err
	}

	askSp, err := pp.deserializeAddressSecretKeySp(serializedASKSp)
	if err != nil {
		return nil, nil, err
	}

	return apk, askSp, nil
}

//	CoinAddress and Keys Parse	end

//	helper functions	end

//	sanity check functions	begin

// AddressPublicKeyForRingSanityCheck checks whether the input AddressPublicKeyForRing is well-from.
// (1) addressPublicKeyForRing is not nil,
// (2) addressPublicKeyForRing.t is not nil and is well-form
// (3) addressPublicKeyForRing.e is well-form
// todo: review by 2024.06
// reviewed by Ocean
func (pp *PublicParameter) AddressPublicKeyForRingSanityCheck(addressPublicKeyForRing *AddressPublicKeyForRing) bool {
	if addressPublicKeyForRing == nil {
		return false
	}

	if addressPublicKeyForRing.t == nil {
		return false
	}
	if len(addressPublicKeyForRing.t.polyANTTs) != pp.paramKA {
		return false
	}
	for i := 0; i < pp.paramKA; i++ {
		if !pp.PolyANTTSanityCheck(addressPublicKeyForRing.t.polyANTTs[i]) {
			return false
		}
	}

	if !pp.PolyANTTSanityCheck(addressPublicKeyForRing.e) {
		return false
	}

	return true
}

// AddressSecretKeyForRingSanityCheck checks whether the input AddressSecretKeyForRing is well-from.
// (1) addressSecretKeyForRing is not nil,
// (2) addressSecretKeyForRing.AddressSecretKeySp.s is well-form, including the normal in the legal scope
// (3) addressSecretKeyForRing.AddressSecretKeySn.ma is well-form
// added by Alice, 2024.07.01
// todo: review by 2024.07
func (pp *PublicParameter) AddressSecretKeyForRingSanityCheck(addressSecretKeyForRing *AddressSecretKeyForRing) bool {
	if addressSecretKeyForRing == nil {
		return false
	}

	if addressSecretKeyForRing.AddressSecretKeySp == nil || addressSecretKeyForRing.AddressSecretKeySp.s == nil {
		return false
	}
	if len(addressSecretKeyForRing.AddressSecretKeySp.s.polyAs) != pp.paramLA {
		return false
	}
	for i := 0; i < pp.paramLA; i++ {
		if !pp.PolyASanityCheck(addressSecretKeyForRing.AddressSecretKeySp.s.polyAs[i]) {
			return false
		}

		if addressSecretKeyForRing.AddressSecretKeySp.s.polyAs[i].infNorm() > 2 {
			// Note that pp.paramGammaA = 2
			return false
		}
	}

	if addressSecretKeyForRing.AddressSecretKeySn == nil {
		return false
	}

	if !pp.PolyANTTSanityCheck(addressSecretKeyForRing.AddressSecretKeySn.ma) {
		return false
	}

	return true
}

// AddressPublicKeyForSingleSanityCheck checks whether the input AddressPublicKeyForSingle is well-from.
// (1) addressPublicKeyForSingle is not nil,
// (2) addressPublicKeyForRing.t is not nil and is well-form
// todo: review by 2024.06
func (pp *PublicParameter) AddressPublicKeyForSingleSanityCheck(addressPublicKeyForSingle *AddressPublicKeyForSingle) bool {
	if addressPublicKeyForSingle == nil {
		return false
	}

	if addressPublicKeyForSingle.t == nil {
		return false
	}
	if len(addressPublicKeyForSingle.t.polyANTTs) != pp.paramKA {
		return false
	}
	for i := 0; i < pp.paramKA; i++ {
		if !pp.PolyANTTSanityCheck(addressPublicKeyForSingle.t.polyANTTs[i]) {
			return false
		}
	}

	return true
}

// AddressSecretKeyForSingleSanityCheck checks whether the input AddressSecretKeyForSingle is well-from.
// (1) addressSecretKeyForSingle is not nil,
// (2) addressSecretKeyForSingle.AddressSecretKeySp.s is well-form, including the normal in the legal scope
// added by Alice, 2024.07.01
// todo: review by 2024.07
// reviewed by Ocean
func (pp *PublicParameter) AddressSecretKeyForSingleSanityCheck(addressSecretKeyForSingle *AddressSecretKeyForSingle) bool {
	if addressSecretKeyForSingle == nil {
		return false
	}

	if addressSecretKeyForSingle.AddressSecretKeySp == nil || addressSecretKeyForSingle.AddressSecretKeySp.s == nil {
		return false
	}
	if len(addressSecretKeyForSingle.AddressSecretKeySp.s.polyAs) != pp.paramLA {
		return false
	}
	for i := 0; i < pp.paramLA; i++ {
		if !pp.PolyASanityCheck(addressSecretKeyForSingle.AddressSecretKeySp.s.polyAs[i]) {
			return false
		}

		if addressSecretKeyForSingle.AddressSecretKeySp.s.polyAs[i].infNorm() > 2 {
			// Note that pp.paramGammaA = 2
			return false
		}
	}

	return true
}

//	sanity check functions	end
