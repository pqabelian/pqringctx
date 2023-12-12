package pqringctx

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

type AddressSecretKeySp struct {
	//	s \in (S_{\gamma_a})^{L_a}, where \gamma_a is small, say 5 at this moment.
	//	As s' infinity normal lies in [-5, 5], here we define s as PolyAVec, rather than PolyANTTVec.
	s *PolyAVec
}
type AddressSecretKeySn struct {
	ma *PolyANTT
}

type AddressPublicKeyForRing struct {
	t *PolyANTTVec // directly in NTT form
	e *PolyANTT
}
type AddressSecretKeyForRing struct {
	*AddressSecretKeySp
	*AddressSecretKeySn
}

type AddressPublicKeyForSingle struct {
	t *PolyANTTVec // directly in NTT form
}
type AddressSecretKeyForSingle struct {
	*AddressSecretKeySp
}

// CoinAddressKeyForPKRingGen generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.05
func (pp *PublicParameter) CoinAddressKeyForPKRingGen(randSeed []byte) (coinAddress []byte, coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte, err error) {
	apk, ask, err := pp.addressKeyForRingGen(randSeed)
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

	coinAddress = make([]byte, 1+len(serializedAPK))
	coinAddress[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinAddress[1:], serializedAPK)

	coinSpendSecretKey = make([]byte, 1+len(serializedASKSp))
	coinSpendSecretKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSpendSecretKey[1:], serializedASKSp)

	coinSerialNumberSecretKey = make([]byte, 1+len(serializedASKSn))
	coinSerialNumberSecretKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSerialNumberSecretKey[1:], serializedASKSn)

	return coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, nil

	//return nil, nil, nil, err
}

// CoinAddressKeyForPKHSingleGen generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy,
// where the CoinAddress will be a hash, and used in a single manner.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
// reviewed on 2023.12.05
// reviewed on 2023.12.07
func (pp *PublicParameter) CoinAddressKeyForPKHSingleGen(randSeed []byte) (coinAddress []byte, coinSpendSecretKey []byte, err error) {
	apk, ask, err := pp.addressKeyForSingleGen(randSeed)
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
	coinAddress = make([]byte, 1+HashOutputBytesLen)
	coinAddress[0] = byte(CoinAddressTypePublicKeyHashForSingle)
	copy(coinAddress[1:], apkHash)

	coinSpendSecretKey = make([]byte, 1+len(serializedAPK)+len(serializedASKSp))
	coinSpendSecretKey[0] = byte(CoinAddressTypePublicKeyHashForSingle)
	copy(coinSpendSecretKey[1:], serializedAPK)
	copy(coinSpendSecretKey[1+len(serializedAPK):], serializedASKSp)

	return coinAddress, coinSpendSecretKey, nil

	//	return nil, nil, err
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
// reviewed on 2023.12.07
func (pp *PublicParameter) CoinValueKeyGen(randSeed []byte) (coinValuePublicKey []byte, coinValueSecretKey []byte, err error) {
	return pqringctxkem.KeyGen(pp.paramKem, randSeed, pp.paramKeyGenSeedBytesLen)
}

// CoinAddress and CoinKeys	begin

// ExtractCoinAddressTypeFromCoinAddress extract the CoinAddressType from the input coinAddress.
// reviewed on 2023.12.05
// reviewed on 2023.12.07
func (pp *PublicParameter) ExtractCoinAddressTypeFromCoinAddress(coinAddress []byte) (CoinAddressType, error) {
	n := len(coinAddress)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.addressPublicKeyForRingSerializeSize() {
		return CoinAddressTypePublicKeyForRingPre, nil

	} else if n == 1+pp.addressPublicKeyForRingSerializeSize() {
		//	should be a coinAddress generated by CoinAddressKeyForPKRingGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyForRing, nil

	} else if n == 1+HashOutputBytesLen {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyHashForSingle, nil

	}

	return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinAddress: the input coinAddress has a length that is not supported")
}

// ExtractCoinAddressTypeFromCoinSpendSecretKey extracts coinAddressType from the input coinSpendSecretKey.
// reviewed on 2023.12.12
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
			return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSnSecretKey: the length of the input coinSnSecretKey and the extracted coinAddressType mismatch")
		}
		return CoinAddressTypePublicKeyForRing, nil

	} else if n == 0 {
		//	should be a coinAddress generated by CoinAddressKeyForPKHSingleGen, where the coinSnSecretKey is nil
		return CoinAddressTypePublicKeyHashForSingle, nil
	}

	return 0, fmt.Errorf("ExtractCoinAddressTypeFromCoinSnSecretKey: the input coinSnSecretKey has a length that is not supported")
}

// GetCoinAddressSize returns the CoinAddress size corresponding to the input CoinAddressType.
// reviewed on 2023.12.05
func (pp *PublicParameter) GetCoinAddressSize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressPublicKeyForRingSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressPublicKeyForRingSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 1 + HashOutputBytesLen, nil
	default:
		return 0, errors.New("GetCoinAddressSize: the input coinAddressType is not supported")
	}
}

// GetCoinSpendSecretKeySize returns the size of CoinSpendSecretKey, according to the input CoinAddressType.
// reviewed on 2023.12.12
func (pp *PublicParameter) GetCoinSpendSecretKeySize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressSecretKeySpSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressSecretKeySpSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 1 + pp.addressPublicKeyForSingleSerializeSize() + pp.addressSecretKeySpSerializeSize(), nil
	default:
		return 0, fmt.Errorf("GetCoinSpendSecretKeySize: the input coinAddressType is not supported")
	}
}

// GetCoinSerialNumberSecretKeySize returns the size of CoinSerialNumberSecretKey, according to the input CoinAddressType.
// reviewed on 2023.12.12
func (pp *PublicParameter) GetCoinSerialNumberSecretKeySize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.addressSecretKeySnSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.addressSecretKeySnSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 0, nil
	default:
		return 0, errors.New("GetCoinSerialNumberSecretKeySize: the input coinAddressType is not supported")
	}
}

// GetCoinValuePublicKeySize returns the CoinValuePublicKey size
// todo: to review
func (pp *PublicParameter) GetCoinValuePublicKeySize() int {
	// todo(MPL):
	return 1188
}

func (pp *PublicParameter) GetCoinValueSecretKeySize() int {
	// todo(MPL):
	return 0
}

//	CoinAddress and CoinKeys	end

//	helper functions	begin

// addressKeyForRingGen generates (AddressPublicKeyForRing, AddressSecretKeyForRing) from the input seed.
// If the seed is empty, this algorithm is a randomized algorithm.
// If the seed is not empty and has the correct length (which can be obtained by GetParamKeyGenSeedBytesLen() ), it is a deterministic algorithm,
// where all randomness will be derived from the input seed.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) addressKeyForRingGen(seed []byte) (apk *AddressPublicKeyForRing, ask *AddressSecretKeyForRing, err error) {
	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, fmt.Errorf("AddressKeyForRingGen: the length of seed is invalid")
	}
	if seed == nil {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	}

	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramKeyGenSeedBytesLen)

	copy(tmp, seed)
	s, err := pp.expandAddressSKsp(tmp)
	if err != nil {
		return nil, nil, err
	}

	copy(tmp, seed)
	ma, err := pp.expandAddressSKsn(tmp)
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
	return apk, ask, nil
}

// addressKeyForRingVerify check whether the input AddressPublicKeyForRing and AddressSecretKeyForRing match.
// reviewed on 2023.12.05.
func (pp *PublicParameter) addressKeyForRingVerify(apk *AddressPublicKeyForRing, ask *AddressSecretKeyForRing) (valid bool, hints string) {
	//	verify the normal of ask.s
	if !pp.isAddressSKspNormalInBound(ask.s) {
		return false, "the normal of AddressSecretKeySp is not in the expected bound"
	}

	// compute t = A * s
	s_ntt := pp.NTTPolyAVec(ask.s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	// compute e = <a,s>+ma
	e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ask.ma)

	// compare computed (t,e) and (apk.t, apk.e)
	if !(pp.PolyANTTVecEqualCheck(t, apk.t) && pp.PolyANTTEqualCheck(e, apk.e)) {
		return false, "the AddressPublicKeyForRing computed from AddressSecretKeyForRing does not match the input one"
	}

	return true, ""
}

// addressKeyForSingleGen generates (AddressPublicKeyForSingle, AddressSecretKeyForSingle) from the input seed.
// If the seed is empty, this algorithm is a randomized algorithm.
// If the seed is not empty and has the correct length (which can be obtained by GetParamKeyGenSeedBytesLen() ), it is a deterministic algorithm,
// where all randomness will be derived from the input seed.
// reviewed on 2023.12.05.
func (pp *PublicParameter) addressKeyForSingleGen(seed []byte) (apk *AddressPublicKeyForSingle, ask *AddressSecretKeyForSingle, err error) {
	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, errors.New("AddressKeyForSingleGen: the length of seed is invalid")
	}
	if seed == nil {
		seed = RandomBytes(pp.paramKeyGenSeedBytesLen)
	}

	// this temporary byte slice is for protect seed unmodified
	tmp := make([]byte, pp.paramKeyGenSeedBytesLen)

	copy(tmp, seed)
	s, err := pp.expandAddressSKsp(tmp)
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

// addressKeyForSingleVerify verify whther the input AddressPublicKeyForSingle and AddressSecretKeyForSingle match.
// reviewed on 2023.12.05.
func (pp *PublicParameter) addressKeyForSingleVerify(apk *AddressPublicKeyForSingle, ask *AddressSecretKeyForSingle) (valid bool, hints string) {
	//	verify the normal of ask.s
	if !pp.isAddressSKspNormalInBound(ask.s) {
		return false, "the normal of AddressSecretKeySp is not in the expected bound"
	}

	// compute t = A * s
	s_ntt := pp.NTTPolyAVec(ask.s)
	t := pp.PolyANTTMatrixMulVector(pp.paramMatrixA, s_ntt, pp.paramKA, pp.paramLA)

	//// compute e = <a,s>+ma
	//e := pp.PolyANTTAdd(pp.PolyANTTVecInnerProduct(pp.paramVectorA, s_ntt, pp.paramLA), ask.ma)

	// compare computed (t,e) and (apk.t, apk.e)
	//	if !(pp.PolyANTTVecEqualCheck(t, apk.t) && pp.PolyANTTEqualCheck(e, apk.e)) {
	if !pp.PolyANTTVecEqualCheck(t, apk.t) {
		return false, "the AddressPublicKeyForSingle computed from AddressSecretKeyForSingle does not match the input one"
	}

	return true, ""
}

// AddressPublicKeyForRingSerializeSize returns the serialized size for AddressPublicKeyForRing.
// review on 2023.12.04.
// reviewed on 2023.12.05.
func (pp *PublicParameter) addressPublicKeyForRingSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t) + pp.PolyANTTSerializeSize()
	return (pp.paramKA + 1) * pp.PolyANTTSerializeSize()
}

// serializeAddressPublicKeyForRing serialize the input AddressPublicKeyForRing to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) serializeAddressPublicKeyForRing(apk *AddressPublicKeyForRing) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil || apk.e == nil {
		return nil, errors.New("serializeAddressPublicKeyForRing: there is nil pointer in AddressPublicKeyForRing")
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, errors.New("serializeAddressPublicKeyForRing: the format of AddressPublicKeyForRing does not match the design")
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
func (pp *PublicParameter) addressPublicKeyForSingleSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t)
	return pp.paramKA * pp.PolyANTTSerializeSize()
}

// serializeAddressPublicKeyForSingle serialize the input AddressPublicKeyForSingle to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) serializeAddressPublicKeyForSingle(apk *AddressPublicKeyForSingle) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil {
		return nil, fmt.Errorf("serializeAddressPublicKeyForSingle: there is nil pointer in AddressPublicKeyForSingle")
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, fmt.Errorf("serializeAddressPublicKeyForSingle: the format of AddressPublicKeyForSingle does not match the design")
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
func (pp *PublicParameter) addressSecretKeySpSerializeSize() int {
	// s polyAVec with length L_a, wih
	return pp.paramLA * pp.PolyASerializeSizeGamma()
}

// serializeAddressSecretKeySp serialize the input AddressSecretKeySp to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) serializeAddressSecretKeySp(askSp *AddressSecretKeySp) ([]byte, error) {
	var err error
	if askSp == nil || askSp.s == nil {
		return nil, fmt.Errorf("serializeAddressSecretKeySp: there is nil pointer in AddressSecretKeySp")
	}

	if len(askSp.s.polyAs) != pp.paramLA {
		return nil, fmt.Errorf("the format of AddressSecretKeySp does not match the design")
	}

	// s is in its poly form and it has infinite normal in [-Gamma_a, Gamma_a] where Gamma_a is 5 at this moment,
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
func (pp *PublicParameter) addressSecretKeySnSerializeSize() int {
	return pp.PolyANTTSerializeSize()
}

// serializeAddressSecretKeySn serialize the input AddressSecretKeySn to []byte.
// reviewed on 2023.12.05.
func (pp *PublicParameter) serializeAddressSecretKeySn(askSn *AddressSecretKeySn) ([]byte, error) {
	var err error
	if askSn == nil || askSn.ma == nil {
		return nil, errors.New("serializeAddressSecretKeySn: there is nil pointer in AddressSecretKeySn")
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
func (pp *PublicParameter) deserializeAddressSecretKeySn(serializedASKSn []byte) (*AddressSecretKeySn, error) {
	r := bytes.NewReader(serializedASKSn)
	ma, err := pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressSecretKeySn{ma}, nil
}

//	helper functions	end
