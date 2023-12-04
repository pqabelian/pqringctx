package pqringctx

import (
	"bytes"
	"errors"
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

// CoinAddressKeyForRingGen generates coinAddress, coinSpendKey, and coinSnKey
// for the key which will be used to host the coins with full-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func (pp *PublicParameter) CoinAddressKeyForRingGen(randSeed []byte) (coinAddress []byte, coinSpendKey []byte, coinSnKey []byte, err error) {
	apk, ask, err := pp.addressKeyForRingGen(randSeed)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedAPK, err := pp.SerializeAddressPublicKeyForRing(apk)
	if err != nil {
		return nil, nil, nil, err
	}

	serializedASKSp, err := pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
	if err != nil {
		return nil, nil, nil, err
	}
	serializedASKSn, err := pp.SerializeAddressSecretKeySn(ask.AddressSecretKeySn)
	if err != nil {
		return nil, nil, nil, err
	}

	coinAddress = make([]byte, 1+len(serializedAPK))
	coinAddress[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinAddress[1:], serializedAPK)

	coinSpendKey = make([]byte, 1+len(serializedASKSp))
	coinSpendKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSpendKey[1:], serializedASKSp)

	coinSnKey = make([]byte, 1+len(serializedASKSn))
	coinSnKey[0] = byte(CoinAddressTypePublicKeyForRing)
	copy(coinSnKey[1:], serializedASKSn)

	return coinAddress, coinSpendKey, coinSnKey, nil

	//return nil, nil, nil, err
}

// CoinAddressKeyForSingleGen generates coinAddress and coinSpendKey
// for the key which will be used to host the coins with pseudonym-privacy.
// Note that keys are purely in cryptography, we export bytes,
// and packages the cryptographic details in pqringctx.
func (pp *PublicParameter) CoinAddressKeyForSingleGen(seed []byte) (coinAddress []byte, coinSpendKey []byte, err error) {
	apk, ask, err := pp.addressKeyForSingleGen(seed)
	if err != nil {
		return nil, nil, err
	}

	serializedAPK, err := pp.SerializeAddressPublicKeyForSingle(apk)
	if err != nil {
		return nil, nil, err
	}

	serializedASKSp, err := pp.SerializeAddressSecretKeySp(ask.AddressSecretKeySp)
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

	coinSpendKey = make([]byte, 1+len(serializedASKSp))
	coinSpendKey[0] = byte(CoinAddressTypePublicKeyHashForSingle)
	copy(coinSpendKey[1:], serializedASKSp)

	return coinAddress, coinSpendKey, nil

	//	return nil, nil, err
}

// CoinValueKeyGen generates serializedValuePublicKey and serializedValueSecretKey,
// which will be used to transmit the (value, randomness) pair of the value-commitment to the coin owner.
// Note that by default, pqringctx transmits the (value, randomness) pair by on-chain data,
// i.e., the ciphertexts are included in Txo.
// As the encryption/transmit of (value, randomness) pair is independent from the coinAddress part,
// we use a standalone ValueKeyGen algorithm to generate these keys.
func (pp *PublicParameter) CoinValueKeyGen(randSeed []byte) (serializedValuePublicKey []byte, serializedValueSecretKey []byte, err error) {
	return pqringctxkem.KeyGen(pp.paramKem, randSeed, pp.paramKeyGenSeedBytesLen)
}

func (pp *PublicParameter) addressKeyForRingGen(seed []byte) (apk *AddressPublicKeyForRing, ask *AddressSecretKeyForRing, err error) {
	// check the validity of the length of seed
	if seed != nil && len(seed) != pp.paramKeyGenSeedBytesLen {
		return nil, nil, errors.New("AddressKeyForRingGen: the length of seed is invalid")
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
func (pp *PublicParameter) AddressPublicKeyForRingSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t) + pp.PolyANTTSerializeSize()
	return (pp.paramKA + 1) * pp.PolyANTTSerializeSize()
}

func (pp *PublicParameter) SerializeAddressPublicKeyForRing(apk *AddressPublicKeyForRing) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil || apk.e == nil {
		return nil, errors.New("SerializeAddressPublicKeyForRing: there is nil pointer in AddressPublicKeyForRing")
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, errors.New("SerializeAddressPublicKeyForRing: the format of AddressPublicKeyForRing does not match the design")
	}

	length := pp.AddressPublicKeyForRingSerializeSize()
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
func (pp *PublicParameter) DeserializeAddressPublicKeyForRing(serializedAPKForRing []byte) (*AddressPublicKeyForRing, error) {
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

func (pp *PublicParameter) AddressPublicKeyForSingleSerializeSize() int {
	//return pp.PolyANTTVecSerializeSize(a.t)
	return pp.paramKA * pp.PolyANTTSerializeSize()
}

func (pp *PublicParameter) SerializeAddressPublicKeyForSingle(apk *AddressPublicKeyForSingle) ([]byte, error) {
	var err error
	if apk == nil || apk.t == nil {
		return nil, errors.New("SerializeAddressPublicKeyForSingle: there is nil pointer in AddressPublicKeyForSingle")
	}
	if len(apk.t.polyANTTs) != pp.paramKA {
		return nil, errors.New("SerializeAddressPublicKeyForSingle: the format of AddressPublicKeyForSingle does not match the design")
	}

	length := pp.AddressPublicKeyForSingleSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))
	for i := 0; i < pp.paramKA; i++ {
		err = pp.writePolyANTT(w, apk.t.polyANTTs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressPublicKeyForSingle(serializedAPKForSingle []byte) (*AddressPublicKeyForSingle, error) {
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

// AddressSecretKeySpSerializeSize() return the fixed size of AddressSecretKeySp
func (pp *PublicParameter) AddressSecretKeySpSerializeSize() int {
	// s polyAVec with length L_a, wih
	return pp.paramLA * pp.PolyASerializeSizeGamma()
}
func (pp *PublicParameter) SerializeAddressSecretKeySp(askSp *AddressSecretKeySp) ([]byte, error) {
	var err error
	if askSp == nil || askSp.s == nil {
		return nil, errors.New("SerializeAddressSecretKeySp: there is nil pointer in AddressSecretKeySp")
	}

	if len(askSp.s.polyAs) != pp.paramLA {
		return nil, errors.New("the format of AddressSecretKeySp does not match the design")
	}

	// s is in its poly form and it has infinite normal in [-Gamma_a, Gamma_a] where Gamma_a is 5 at this moment,
	// we serialize its poly from.
	askSpLen := pp.AddressSecretKeySpSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, askSpLen))
	for i := 0; i < pp.paramLA; i++ {
		err = pp.writePolyAGamma(w, askSp.s.polyAs[i])
		if err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (pp *PublicParameter) DeserializeAddressSecretKeySp(serializedASKSp []byte) (*AddressSecretKeySp, error) {
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

func (pp *PublicParameter) AddressSecretKeySnSerializeSize() int {
	return pp.PolyANTTSerializeSize()
}
func (pp *PublicParameter) SerializeAddressSecretKeySn(askSn *AddressSecretKeySn) ([]byte, error) {
	var err error
	if askSn == nil || askSn.ma == nil {
		return nil, errors.New("SerializeAddressSecretKeySn: there is nil pointer in AddressSecretKeySn")
	}
	snLength := pp.AddressSecretKeySnSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, snLength))
	err = pp.writePolyANTT(w, askSn.ma)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}
func (pp *PublicParameter) DeserializeAddressSecretKeySn(serializedASKSn []byte) (*AddressSecretKeySn, error) {
	r := bytes.NewReader(serializedASKSn)
	ma, err := pp.readPolyANTT(r)
	if err != nil {
		return nil, err
	}
	return &AddressSecretKeySn{ma}, nil
}

func (pp *PublicParameter) ExtractCoinAddressTypeFromCoinAddress(coinAddress []byte) (CoinAddressType, error) {
	n := len(coinAddress)
	//	Before Fork-MLP, the coinAddress is the serializedAPK by PQRingCT,
	//	and those addresses are CoinAddressTypePublicKeyForRing in the setting of PQRingCTX.
	//	To be compatible, we  first handle this.
	//	Note that the underlying crypto-params of PQRingCTX are the same as PQRingCT,
	//	and AddressPublicKeyForRing in PQRingCTX is the same as AddressPublicKey in PQRingCT.
	if n == pp.AddressPublicKeyForRingSerializeSize() {
		return CoinAddressTypePublicKeyForRingPre, nil
	} else if n == 1+pp.AddressPublicKeyForRingSerializeSize() {
		//	should be a coinAddress generated by AddressKeyForRingGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return 0, errors.New("ExtractCoinAddressType: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}

		return CoinAddressTypePublicKeyForRing, nil
	} else if n == 1+HashOutputBytesLen {
		//	should be a coinAddress generated by AddressKeyForSingleGen
		coinAddressType := CoinAddressType(coinAddress[0])
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return 0, errors.New("ExtractCoinAddressType: the length of the input coinAddress and the extracted coinAddressType mismatch")
		}

		return CoinAddressTypePublicKeyHashForSingle, nil
	}

	return 0, errors.New("ExtractCoinAddressType: the input coinAddress has a length that is not supported")
}

func (pp *PublicParameter) GetCoinAddressSize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.AddressPublicKeyForRingSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return 1 + pp.AddressPublicKeyForRingSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return 1 + HashOutputBytesLen, nil
	default:
		return 0, errors.New("GetCoinAddressSize: the input coinAddressType is not supported")
	}
}

func (pp *PublicParameter) GetCoinValuePublicKeySize() int {
	// todo(MPL):
	return 1188
}
