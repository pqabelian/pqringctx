package pqringctx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

// TxoMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the Txos in one CoinbaseTxMLP/TransferTxMLP could be hosted on addresses for different privacy-levels
// and consequently have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxoMLP []byte
// Note: We do not define standalone structure for Txo.
//
//	Instead, we directly use []byte in Txs to denote Txo, rather than using a structure.
//	This is because:
//	Txo is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of Txo.
//	PQRINGCTX will be responsible for generating Txo and providing service/API on the generated Txo.
//

// TxoMLP defines the interface for Txo.
// reviewed on 2023.12.05
type TxoMLP interface {
	CoinAddressType() CoinAddressType
}

// TxoRCTPre defines the Txo with RingCT-privacy, but the coinAddress has the initial format.
// This is to achieve back-compatibility with the previous Txos (with RingCT-privacy).
// reviewed on 2023.12.05
type TxoRCTPre struct {
	coinAddressType         CoinAddressType
	addressPublicKeyForRing *AddressPublicKeyForRing
	valueCommitment         *ValueCommitment
	vct                     []byte //	value ciphertext
	ctKemSerialized         []byte //  ciphertext for kem
}

// CoinAddressType is a method that all TxoMLP instance shall implement, which returns the coinAddressType.
// reviewed on 2023.12.05
func (txoRCTPre *TxoRCTPre) CoinAddressType() CoinAddressType {
	return txoRCTPre.coinAddressType
}

// TxoRCT defines the Txo with RingCT-privacy.
// reviewed on 2023.12.05
// todo: review
type TxoRCT struct {
	coinAddressType         CoinAddressType
	addressPublicKeyForRing *AddressPublicKeyForRing
	publicRand              []byte
	detectorTag             []byte
	valueCommitment         *ValueCommitment
	vct                     []byte //	value ciphertext
	ctKemSerialized         []byte //  ciphertext for kem
}

// CoinAddressType is the method that all TxoMLP instance shall implement, which returns the coinAddressType.
// reviewed on 2023.12.05
func (txoRCT *TxoRCT) CoinAddressType() CoinAddressType {
	return txoRCT.coinAddressType
}

// TxoSDN defines the Txo with Pseudonym-privacy.
// reviewed on 2023.12.05
type TxoSDN struct {
	coinAddressType               CoinAddressType
	addressPublicKeyForSingleHash []byte
	publicRand                    []byte
	detectorTag                   []byte
	value                         uint64
}

// CoinAddressType is the method that all TxoMLP instance shall implement, which returns the coinAddressType.
// reviewed on 2023.12.05
func (txoSDN *TxoSDN) CoinAddressType() CoinAddressType {
	return txoSDN.coinAddressType
}

//	TXO	Gen		begin
//
// txoRCTPreGen() returns a transaction output and the randomness used to generate the commitment.
// It is same as the txoGen in pqringct, with coinAddress be exactly the serializedAddressPublicKey.
// Note that the coinAddress should be serializedAddressPublicKeyForRing = serializedAddressPublicKey (in pqringct).
// Note that the vpk should be serializedValuePublicKey = serializedViewPublicKey (in pqringct).
// reviewed on 2023.12.07
func (pp *PublicParameter) txoRCTPreGen(coinAddress []byte, coinValuePublicKey []byte, value uint64) (txo *TxoRCTPre, cmtr *PolyCNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	//		todo: pp.Encaps ? 2023.12.13
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, coinValuePublicKey)
	if err != nil {
		return nil, nil, err
	}

	//	expand the kappa to PolyCVec with length Lc
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr = pp.NTTPolyCVec(cmtr_poly)

	mtmp := pp.intToBinary(value)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo_done: the vc should have length only N, to prevent the unused D-N bits of leaking information
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	vpt, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		return nil, nil, err
	}
	vct := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vct[i] = sk[i] ^ vpt[i]
	}
	// This is hard coded, based on the  value of N, and the algorithm encodeTxoValueToBytes().
	//	N = 51, encodeTxoValueToBytes() uses only the lowest 3 bits of 7-th byte.
	vct[6] = vct[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th,50th, 49th bits to be their real value.
	//	By this way, we can avoid the leaking the corresponding bits of pad.

	//rettxo := &Txo{
	//	apk,
	//	cmt,
	//	vct,
	//	CtKemSerialized,
	//}

	// Parse coinAddress
	addressPublicKeyForRing, err := pp.deserializeAddressPublicKeyForRing(coinAddress)
	if err != nil {
		return nil, nil, err
	}
	retTxo := &TxoRCTPre{
		CoinAddressTypePublicKeyForRingPre,
		addressPublicKeyForRing,
		cmt,
		vct,
		CtKemSerialized,
	}

	return retTxo, cmtr, nil
}

// txoRCTGen() returns a transaction output and the randomness used to generate the commitment.
// Note that the coinAddress should be 1 byte (CoinAddressType) + serializedAddressPublicKeyForRing.
// Note that the vpk should be 1 byte (CoinAddressType) + serializedValuePublicKey.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) txoRCTGen(coinAddress []byte, coinValuePublicKey []byte, value uint64) (txo *TxoRCT, cmtr *PolyCNTTVec, err error) {

	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	//		todo: pp.Encaps ? 2023.12.13
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, coinValuePublicKey)
	if err != nil {
		return nil, nil, err
	}

	//	expand the kappa to PolyCVec with length Lc
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	cmtr = pp.NTTPolyCVec(cmtr_poly)

	mtmp := pp.intToBinary(value)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	cmt := &ValueCommitment{}
	cmt.b = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	cmt.c = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	//	vc = m ^ sk
	//	todo_done: the vc should have length only N, to prevent the unused D-N bits of leaking information
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return nil, nil, err
	}
	vpt, err := pp.encodeTxoValueToBytes(value)
	if err != nil {
		return nil, nil, err
	}
	vct := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vct[i] = sk[i] ^ vpt[i]
	}
	// This is hard coded, based on the  value of N, and the algorithm encodeTxoValueToBytes().
	//	N = 51, encodeTxoValueToBytes() uses only the lowest 3 bits of 7-th byte.
	vct[6] = vct[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th,50th, 49th bits to be their real value.
	//	By this way, we can avoid the leaking the corresponding bits of pad.

	//rettxo := &Txo{
	//	apk,
	//	cmt,
	//	vct,
	//	CtKemSerialized,
	//}

	// parse coinAddress
	apkSize := pp.addressPublicKeyForRingSerializeSize()
	publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
	detectorTagSize := pp.GetParamMACOutputBytesLen()
	if len(coinAddress) != 1+apkSize+publicRandSize+detectorTagSize {
		return nil, nil, fmt.Errorf("txoRCTGen: the input coinAddress has an invalid length (%d)", len(coinAddress))
	}
	coinAddressType := CoinAddressType(coinAddress[0])
	if coinAddressType != CoinAddressTypePublicKeyForRing {
		return nil, nil, fmt.Errorf("txoRCTGen: the input coinAddress's coinAddressType (%d) is not CoinAddressTypePublicKeyForRing", coinAddressType)
	}

	serializedAddressPublicKeyForRing := make([]byte, apkSize)
	publicRand := make([]byte, publicRandSize)
	detectorTag := make([]byte, detectorTagSize)

	copy(serializedAddressPublicKeyForRing, coinAddress[1:1+apkSize])
	copy(publicRand, coinAddress[1+apkSize:1+apkSize+publicRandSize])
	copy(detectorTag, coinAddress[1+apkSize+publicRandSize:])

	addressPublicKeyForRing, err := pp.deserializeAddressPublicKeyForRing(serializedAddressPublicKeyForRing)
	if err != nil {
		return nil, nil, err
	}

	retTxo := &TxoRCT{
		CoinAddressTypePublicKeyForRing,
		addressPublicKeyForRing,
		publicRand,
		detectorTag,
		cmt,
		vct,
		CtKemSerialized,
	}

	return retTxo, cmtr, nil
}

// txoSDNGen() returns a transaction output and the randomness used to generate the commitment.
// Note that coinAddress should be 1 byte (CoinAddressType) + AddressPublicKeyForSingleHash.
// reviewed on 2023.12.07
func (pp *PublicParameter) txoSDNGen(coinAddress []byte, value uint64) (txo *TxoSDN, err error) {
	// parse coinAddress
	apkHashSize := HashOutputBytesLen
	publicRandSize := pp.GetParamKeyGenPublicRandBytesLen()
	detectorTagSize := pp.GetParamMACOutputBytesLen()
	if len(coinAddress) != 1+apkHashSize+publicRandSize+detectorTagSize {
		return nil, fmt.Errorf("txoSDNGen: the input coinAddress has an invalid length (%d)", len(coinAddress))
	}
	coinAddressType := CoinAddressType(coinAddress[0])
	if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
		return nil, fmt.Errorf("txoSDNGen: the input coinAddress's coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
	}

	addressPublicKeyForSingleHash := make([]byte, apkHashSize)
	publicRand := make([]byte, publicRandSize)
	detectorTag := make([]byte, detectorTagSize)

	copy(addressPublicKeyForSingleHash, coinAddress[1:1+apkHashSize])
	copy(publicRand, coinAddress[1+apkHashSize:1+apkHashSize+publicRandSize])
	copy(detectorTag, coinAddress[1+apkHashSize+publicRandSize:])

	return &TxoSDN{
		CoinAddressTypePublicKeyHashForSingle,
		addressPublicKeyForSingleHash,
		publicRand,
		detectorTag,
		value,
	}, nil
}

//	TXO	Gen		end

// ExtractValueAndRandFromTxoMLP extract the (value, randomness) pair for txoMLP.valueCommitment.
// added on 2023.12.13
// todo: review
// todo: confirm the kem call
func (pp *PublicParameter) ExtractValueAndRandFromTxoMLP(txoMLP TxoMLP, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, cmtr *PolyCNTTVec, err error) {
	if txoMLP == nil {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input txoMLP could not be nil/empty")
	}

	var ctKemSerialized []byte
	var vct []byte
	var valueCommitment *ValueCommitment
	switch txoInst := txoMLP.(type) {
	case *TxoRCTPre:
		ctKemSerialized = txoInst.ctKemSerialized
		vct = txoInst.vct
		valueCommitment = txoInst.valueCommitment

	case *TxoRCT:

		ctKemSerialized = txoInst.ctKemSerialized
		vct = txoInst.vct
		valueCommitment = txoInst.valueCommitment

	case *TxoSDN:
		return txoInst.value, nil, nil

	default:
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input txoMLP is not TxoRCTPre, TxoRCT, or TxoSDN")
	}

	if len(coinValuePublicKey) == 0 || len(coinValueSecretKey) == 0 {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: none of the input (txoMLP, coinValuePublicKey, coinValueSecretKey) could be nil/empty")
	}
	if len(ctKemSerialized) == 0 {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input txoMLP.ctKemSerialized is nil/empty")
	}
	if len(vct) == 0 {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input txoMLP.vct is nil/empty")
	}
	if valueCommitment == nil || valueCommitment.b == nil || valueCommitment.c == nil {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input txoMLP.valueCommitment is nil or has nil field")
	}

	//	Check the validity of (coinValuePublicKey, coinValueSecretKey)
	copiedCoinValueSecretKey := make([]byte, len(coinValueSecretKey))
	copy(copiedCoinValueSecretKey, coinValueSecretKey)
	validValueKey, hints := pp.CoinValueKeyVerify(coinValuePublicKey, copiedCoinValueSecretKey)
	if !validValueKey {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the input (coinValuePublicKey, coinValueSecretKey) is not a valid key pair: %v", hints)
	}
	copy(copiedCoinValueSecretKey, coinValueSecretKey)

	//	decaps to have the K
	kappa, err := pqringctxkem.Decaps(pp.paramKem, ctKemSerialized, copiedCoinValueSecretKey)
	if err != nil {
		return 0, nil, err
	}

	//	decrypt vct to obtain the value
	//	vpt = vct ^ sk
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return 0, nil, err
	}
	if len(sk) != pp.TxoValueBytesLen() {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: the expanded sk for value pad has a wrong length (%d)", len(sk))
	}

	vpt := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vpt[i] = vct[i] ^ sk[i]
	}
	vpt[6] = vpt[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th,50th, 49th bits to be their real value.

	value, err = pp.decodeTxoValueFromBytes(vpt)
	if err != nil {
		return 0, nil, err
	}

	//	expand cmtr and open the commitment
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return 0, nil, err
	}
	cmtr = pp.NTTPolyCVec(cmtr_poly)

	mtmp := pp.intToBinary(value)
	m := &PolyCNTT{coeffs: mtmp}
	// [b c]^T = C*r + [0 m]^T
	b := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmtr, pp.paramKC, pp.paramLC)
	c := pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], cmtr, pp.paramLC),
		m,
	)

	if !pp.PolyCNTTVecEqualCheck(b, valueCommitment.b) || !pp.PolyCNTTEqualCheck(c, valueCommitment.c) {
		return 0, nil, fmt.Errorf("ExtractValueAndRandFromTxoMLP: reject when using the recoverd (value, randomness) to open the commitment")
	}

	return value, cmtr, nil
}

// GetTxoMLPSerializeSizeByCoinAddressType returns the serialize size of a Txo for the input coinAddressType.
// reviewed on 2023.12.07
func (pp *PublicParameter) GetTxoMLPSerializeSizeByCoinAddressType(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.TxoRCTPreSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return pp.TxoRCTSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return pp.TxoSDNSerializeSize(), nil
	default:
		return 0, fmt.Errorf("TxoMLPSerializeSize: unsupported coinAddressType")
	}
}

// TxoMLPSerializeSize returns the serializedSize for the input TxoMLP.
// Note that for the case of txoMLP is a TxoRCTPre, this function must keep the same as pqringct.TxoSerializeSize.
// reviewed on 2023.12.04
// reviewed on 2023.12.07
// reviewed on 2023.12.14
func (pp *PublicParameter) TxoMLPSerializeSize(txoMLP TxoMLP) (int, error) {
	if txoMLP == nil {
		return 0, fmt.Errorf("TxoMLPSerializeSize: the input TxoMLP is nil")
	}

	switch txoMLP.(type) {
	case *TxoRCTPre:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRingPre {
			return 0, fmt.Errorf("TxoMLPSerializeSize: the input TxoMLP is TxoRCTPre, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.TxoRCTPreSerializeSize(), nil

	case *TxoRCT:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRing {
			return 0, fmt.Errorf("TxoMLPSerializeSize: the input TxoMLP is TxoRCT, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.TxoRCTSerializeSize(), nil

	case *TxoSDN:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyHashForSingle {
			return 0, fmt.Errorf("TxoMLPSerializeSize: the input TxoMLP is TxoSDN, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.TxoSDNSerializeSize(), nil
	default:
		return 0, fmt.Errorf("TxoMLPSerializeSize: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

// SerializeTxoMLP serializes the input TxoMLP to []byte.
// Note that, for the case of TxoRCTPre, this must keep the same as pqringct.SerializeTxo.
// reviewed on 2023.12.07
// reviewed on 2023.12.14
func (pp *PublicParameter) SerializeTxoMLP(txoMLP TxoMLP) (serializedTxo []byte, err error) {
	if txoMLP == nil {
		return nil, fmt.Errorf("SerializeTxoMLP: the input TxoMLP is nil")
	}

	switch txoInst := txoMLP.(type) {
	case *TxoRCTPre:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRingPre {
			return nil, fmt.Errorf("SerializeTxoMLP: the input TxoMLP is TxoRCTPre, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.serializeTxoRCTPre(txoInst)

	case *TxoRCT:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRing {
			return nil, fmt.Errorf("SerializeTxoMLP: the input TxoMLP is TxoRCT, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.serializeTxoRCT(txoInst)

	case *TxoSDN:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("SerializeTxoMLP: the input TxoMLP is TxoSDN, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
		}
		return pp.serializeTxoSDN(txoInst)
	default:
		return nil, fmt.Errorf("SerializeTxoMLP: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

// DeserializeTxoMLP deserialize the input []byte to a TxoMLP.
// reviewed on 2023.12.07
func (pp *PublicParameter) DeserializeTxoMLP(serializedTxo []byte) (txoMLP TxoMLP, err error) {
	if len(serializedTxo) == 0 {
		return nil, fmt.Errorf("DeserializeTxoMLP: the input serializedTxo is empty")
	}

	n := len(serializedTxo)
	if n == pp.TxoRCTPreSerializeSize() {
		return pp.deserializeTxoRCTPre(serializedTxo)
	} else if n == pp.TxoRCTSerializeSize() {
		return pp.deserializeTxoRCT(serializedTxo)
	} else if n == pp.TxoSDNSerializeSize() {
		return pp.deserializeTxoSDN(serializedTxo)
	} else {
		return nil, fmt.Errorf("DeserializeTxoMLP: the input serializedTxo has a length that is not supported")
	}
}

// TxoRCTPreSerializeSize returns the serialized size for TxoRCTPre.
// Note that this function must keep the same as pqringct.TxoSerializeSize.
// reviewed on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) TxoRCTPreSerializeSize() int {
	return pp.addressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

// serializeTxoRCTPre serialize the input TxoRCTPre into []byte.
// Note that this must keep the same as pqringct.serializeTxo.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// reviewed on 2023.12.14
func (pp *PublicParameter) serializeTxoRCTPre(txoRCTPre *TxoRCTPre) ([]byte, error) {
	if txoRCTPre == nil || txoRCTPre.addressPublicKeyForRing == nil || txoRCTPre.valueCommitment == nil ||
		len(txoRCTPre.vct) == 0 || len(txoRCTPre.ctKemSerialized) == 0 {
		return nil, fmt.Errorf("serializeTxoRCTPre: there is nil pointer in the input txoRCTPre")
	}

	var err error
	length := pp.TxoRCTPreSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	serializedAddressPublicKey is fixed-length
	serializedAddressPublicKeyForRing, err := pp.serializeAddressPublicKeyForRing(txoRCTPre.addressPublicKeyForRing)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedAddressPublicKeyForRing)
	if err != nil {
		return nil, err
	}

	//	serializedValueCmt is fixed-length
	serializedValueCmt, err := pp.SerializeValueCommitment(txoRCTPre.valueCommitment)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedValueCmt)
	if err != nil {
		return nil, err
	}

	//	txo.Vct is fixed-length
	_, err = w.Write(txoRCTPre.vct)
	if err != nil {
		return nil, err
	}

	//	txo.CtKemSerialized depends on the KEM, the length is not in the scope of pqringctx.
	err = writeVarBytes(w, txoRCTPre.ctKemSerialized)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxoRCTPre deserialize the input []byte to a TxoRCTPre.
// Note that this is the same as deserializeTxo of pqringct.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) deserializeTxoRCTPre(serializedTxoRCTPre []byte) (*TxoRCTPre, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCTPre)

	var apk *AddressPublicKeyForRing
	tmp := make([]byte, pp.addressPublicKeyForRingSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	apk, err = pp.deserializeAddressPublicKeyForRing(tmp)
	if err != nil {
		return nil, err
	}

	var cmt *ValueCommitment
	tmp = make([]byte, pp.ValueCommitmentSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	cmt, err = pp.DeserializeValueCommitment(tmp)
	if err != nil {
		return nil, err
	}

	vct := make([]byte, pp.TxoValueBytesLen())
	_, err = r.Read(vct)
	if err != nil {
		return nil, err
	}

	ctKem, err := readVarBytes(r, MaxAllowedKemCiphertextSize, "TxoRCTPre.CtKemSerialized")
	if err != nil {
		return nil, err
	}

	return &TxoRCTPre{
		CoinAddressTypePublicKeyForRingPre,
		apk,
		cmt,
		vct,
		ctKem}, nil
}

// TxoRCTSerializeSize returns the serialize size for TxoRCT.
// review on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) TxoRCTSerializeSize() int {
	return 1 + // for coinAddressType
		pp.addressPublicKeyForRingSerializeSize() +
		pp.GetParamKeyGenPublicRandBytesLen() +
		pp.GetParamMACOutputBytesLen() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

// serializeTxoRCT serialize the input TxoRCT to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) serializeTxoRCT(txoRCT *TxoRCT) ([]byte, error) {
	if txoRCT == nil || txoRCT.addressPublicKeyForRing == nil || txoRCT.valueCommitment == nil ||
		len(txoRCT.vct) == 0 || len(txoRCT.ctKemSerialized) == 0 {
		return nil, fmt.Errorf("serializeTxoRCT: there is nil pointer in the input txoRCT")
	}

	var err error
	length := pp.TxoRCTSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	// coinAddressType is fixed-length, say 1 byte
	err = w.WriteByte(byte(txoRCT.coinAddressType))
	if err != nil {
		return nil, err
	}

	//	serializedAddressPublicKey is fixed-length
	serializedAddressPublicKeyForRing, err := pp.serializeAddressPublicKeyForRing(txoRCT.addressPublicKeyForRing)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedAddressPublicKeyForRing)
	if err != nil {
		return nil, err
	}

	//	publicRand is fixed length
	_, err = w.Write(txoRCT.publicRand)
	if err != nil {
		return nil, err
	}

	//	detectorTag is fixed length
	_, err = w.Write(txoRCT.detectorTag)
	if err != nil {
		return nil, err
	}

	//	serializedValueCmt is fixed-length
	serializedValueCmt, err := pp.SerializeValueCommitment(txoRCT.valueCommitment)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedValueCmt)
	if err != nil {
		return nil, err
	}

	//	txo.Vct is fixed-length
	_, err = w.Write(txoRCT.vct)
	if err != nil {
		return nil, err
	}

	//	txo.CtKemSerialized depends on the KEM, the length is not in the scope of pqringctx.
	err = writeVarBytes(w, txoRCT.ctKemSerialized)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxoRCT deserialize the input []byte to a TxoRCT.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) deserializeTxoRCT(serializedTxoRCT []byte) (*TxoRCT, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCT)

	var coinAddressType byte
	coinAddressType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if CoinAddressType(coinAddressType) != CoinAddressTypePublicKeyForRing {
		return nil, fmt.Errorf("deserializeTxoRCT: the deserialized coinAddressType is not CoinAddressTypePublicKeyForRing")
	}

	var apk *AddressPublicKeyForRing
	tmp := make([]byte, pp.addressPublicKeyForRingSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	apk, err = pp.deserializeAddressPublicKeyForRing(tmp)
	if err != nil {
		return nil, err
	}

	publicRand := make([]byte, pp.GetParamKeyGenPublicRandBytesLen())
	_, err = r.Read(publicRand)
	if err != nil {
		return nil, err
	}

	detectorTag := make([]byte, pp.GetParamMACOutputBytesLen())
	_, err = r.Read(detectorTag)
	if err != nil {
		return nil, err
	}

	var cmt *ValueCommitment
	tmp = make([]byte, pp.ValueCommitmentSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	cmt, err = pp.DeserializeValueCommitment(tmp)
	if err != nil {
		return nil, err
	}

	vct := make([]byte, pp.TxoValueBytesLen())
	_, err = r.Read(vct)
	if err != nil {
		return nil, err
	}

	ctKem, err := readVarBytes(r, MaxAllowedKemCiphertextSize, "TxoRCTPre.CtKemSerialized")
	if err != nil {
		return nil, err
	}

	return &TxoRCT{
		CoinAddressTypePublicKeyForRing,
		apk,
		publicRand,
		detectorTag,
		cmt,
		vct,
		ctKem}, nil
}

// TxoSDNSerializeSize returns the serialized size for TxoSDN.
// review on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) TxoSDNSerializeSize() int {
	return 1 + // for coinAddressType
		HashOutputBytesLen + //	for addressPublicKeyForSingleHash
		pp.GetParamKeyGenPublicRandBytesLen() + //	for publicRand
		pp.GetParamMACOutputBytesLen() + //	for detectorTag
		8 // for value
}

// serializeTxoSDN serialize the input TxoSDN to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) serializeTxoSDN(txoSDN *TxoSDN) ([]byte, error) {
	if txoSDN == nil || len(txoSDN.addressPublicKeyForSingleHash) == 0 {
		return nil, fmt.Errorf("serializeTxoSDN: there is nil pointer in the input txoSDN")
	}

	var err error
	length := pp.TxoSDNSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	// txoSDN.coinAddressType is fixed-length, say 1 byte
	err = w.WriteByte(byte(txoSDN.coinAddressType))
	if err != nil {
		return nil, err
	}

	//	txoSDN.addressPublicKeyForSingleHash is fixed-length
	_, err = w.Write(txoSDN.addressPublicKeyForSingleHash)
	if err != nil {
		return nil, err
	}

	//	txoSDN.publicRand is fixed-length
	_, err = w.Write(txoSDN.publicRand)
	if err != nil {
		return nil, err
	}

	//	txoSDN.detectorTag is fixed-length
	_, err = w.Write(txoSDN.detectorTag)
	if err != nil {
		return nil, err
	}

	//	txoSDN.value is fixed-length
	err = binarySerializer.PutUint64(w, binary.LittleEndian, txoSDN.value)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxoSDN deserialize the input []byte to a TxoSDN.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
// todo: review
func (pp *PublicParameter) deserializeTxoSDN(serializedTxoSDN []byte) (*TxoSDN, error) {
	var err error
	r := bytes.NewReader(serializedTxoSDN)

	var coinAddressType byte
	coinAddressType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if CoinAddressType(coinAddressType) != CoinAddressTypePublicKeyHashForSingle {
		return nil, fmt.Errorf("deserializeTxoSDN: the deserialized coinAddressType is not CoinAddressTypePublicKeyHashForSingle")
	}

	apkHash := make([]byte, HashOutputBytesLen)
	_, err = r.Read(apkHash)
	if err != nil {
		return nil, err
	}

	publicRand := make([]byte, pp.GetParamKeyGenPublicRandBytesLen())
	_, err = r.Read(publicRand)
	if err != nil {
		return nil, err
	}

	detectorTag := make([]byte, pp.GetParamMACOutputBytesLen())
	_, err = r.Read(detectorTag)
	if err != nil {
		return nil, err
	}

	var value uint64
	value, err = binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	return &TxoSDN{
		CoinAddressTypePublicKeyHashForSingle,
		apkHash,
		publicRand,
		detectorTag,
		value}, nil
}

// ExtractCoinAddressFromSerializedTxo extracts the coinAddress from a serializedTxo, which was generated by SerializeTxoMLP.
// reviewed on 2023.12.12
func (pp *PublicParameter) ExtractCoinAddressFromSerializedTxo(serializedTxo []byte) ([]byte, error) {
	txoMLP, err := pp.DeserializeTxoMLP(serializedTxo)
	if err != nil {
		return nil, err
	}

	coinAddressSize, err := pp.GetCoinAddressSize(txoMLP.CoinAddressType())
	if err != nil {
		return nil, err
	}

	coinAddress := make([]byte, coinAddressSize)
	copy(coinAddress, serializedTxo[:coinAddressSize])
	return coinAddress, nil
}

// GetCoinAddressFromTxoMLP returns the coinAddress for the input txoMLP.
// added on 2023.12.13
// reviewed on 2023.12.14
func (pp *PublicParameter) GetCoinAddressFromTxoMLP(txoMLP TxoMLP) ([]byte, error) {
	if txoMLP == nil {
		return nil, fmt.Errorf("GetCoinAddressFromTxoMLP: the input txoMLP is nil")
	}
	coinAddressType := txoMLP.CoinAddressType()
	coinAddressLen, err := pp.GetCoinAddressSize(coinAddressType)
	if err != nil {
		return nil, err
	}

	//	To keep the same as the serializeTxoMLP algorithm, we use a part of the serializeTxoMLP.
	w := bytes.NewBuffer(make([]byte, 0, coinAddressLen))

	switch txoInst := txoMLP.(type) {
	case *TxoRCTPre:
		if coinAddressType != CoinAddressTypePublicKeyForRingPre {
			return nil, fmt.Errorf("GetCoinAddressFromTxoMLP: the input txoMLP is TxoRCTPre, but the coinAddressType (%d) is not CoinAddressTypePublicKeyForRingPre", coinAddressType)
		}

		//	For TxoRCTPre, coinAddress = serializedApk
		//	serializedAddressPublicKey is fixed-length
		serializedAddressPublicKeyForRing, err := pp.serializeAddressPublicKeyForRing(txoInst.addressPublicKeyForRing)
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedAddressPublicKeyForRing)
		if err != nil {
			return nil, err
		}

	case *TxoRCT:
		if coinAddressType != CoinAddressTypePublicKeyForRing {
			return nil, fmt.Errorf("GetCoinAddressFromTxoMLP: the input txoMLP is TxoRCT, but the coinAddressType (%d) is not CoinAddressTypePublicKeyForRing", coinAddressType)
		}

		//	For TxoRCT, coinAddress = coinAddressType (1 byte) + serializedApk + publicRand + detectorTag
		// coinAddressType is fixed-length, say 1 byte
		err = w.WriteByte(byte(txoInst.coinAddressType))
		if err != nil {
			return nil, err
		}

		//	serializedAddressPublicKey is fixed-length
		serializedAddressPublicKeyForRing, err := pp.serializeAddressPublicKeyForRing(txoInst.addressPublicKeyForRing)
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedAddressPublicKeyForRing)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(txoInst.publicRand)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(txoInst.detectorTag)
		if err != nil {
			return nil, err
		}

	case *TxoSDN:
		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("GetCoinAddressFromTxoMLP: the input txoMLP is TxoSDN, but the coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		//	For TxoSDN, coinAddress = coinAddressType (1 byte) + Hash(serializedApk) + publicRand + detectorTag

		// txoInst.coinAddressType is fixed-length, say 1 byte
		err = w.WriteByte(byte(txoInst.coinAddressType))
		if err != nil {
			return nil, err
		}

		//	txoSDN.addressPublicKeyForSingleHash is fixed-length
		_, err = w.Write(txoInst.addressPublicKeyForSingleHash)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(txoInst.publicRand)
		if err != nil {
			return nil, err
		}

		_, err = w.Write(txoInst.detectorTag)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("GetCoinAddressFromTxoMLP: the input txoMLP is not TxoRCTPre, TxoRCT, or TxoSDN")
	}

	return w.Bytes(), nil
}

// TxoMLPCoinReceive checks whether the input txoMLP belongs to the input coinAddress, and if true,
// it extracts the value from txoMLP using the input (coinValuePublicKey, coinValueSecretKey) pair.
// NOTE: the validity of (coinValuePublicKey, coinValueSecretKey) pair is checked during the value-extraction.
// todo: review
func (pp *PublicParameter) TxoMLPCoinReceive(txoMLP TxoMLP, coinAddress []byte, coinValuePublicKey []byte, coinValueSecretKey []byte) (valid bool, v uint64, err error) {
	if txoMLP == nil {
		return false, 0, fmt.Errorf("TxoMLPCoinReceive: the input txoMLP is nil")
	}

	coinAddressInTxo, err := pp.GetCoinAddressFromTxoMLP(txoMLP)
	if err != nil {
		return false, 0, err
	}

	//	check the address
	if !bytes.Equal(coinAddressInTxo, coinAddress) {
		return false, 0, nil
	}

	//	extract the value
	value, _, err := pp.ExtractValueAndRandFromTxoMLP(txoMLP, coinValuePublicKey, coinValueSecretKey)
	if err != nil {
		return false, 0, err
	}

	return true, value, nil
}

// PseudonymTxoCoinParse parses the input (Pseudonym-Privacy) TxoMLP to its (coinAddress, coinValue) pair, and
// return an err if it is not a Pseudonym-Privacy Txo.
// todo: review
func (pp *PublicParameter) PseudonymTxoCoinParse(txoMLP TxoMLP) (coinAddress []byte, value uint64, err error) {
	if txoMLP == nil {
		return nil, 0, fmt.Errorf("PseudonymTxoCoinParse: the input txoMLP is nil")
	}

	coinAddress, err = pp.GetCoinAddressFromTxoMLP(txoMLP)
	if err != nil {
		return nil, 0, err
	}

	switch txoInst := txoMLP.(type) {
	case *TxoSDN:
		return coinAddress, txoInst.value, nil
	default:
		return nil, 0, fmt.Errorf("PseudonymTxoCoinParse: the input txoMLP is not a TxoSDN")
	}
}

// LedgerTxoSerialNumberGen generates serialNumber for the input LgrTxoMLP, using the input coinSerialNumberSecretKey.
// NOTE: the input coinSerialNumberSecretKey could be nil, for example, when the input LgrTxoMLP is on a CoinAddressTypePublicKeyHashForSingle.
// NOTE: this must keep the same as pqringct.ledgerTXOSerialNumberGen, and consistent with the codes in TransferTxMLPGen.
// todo: review
func (pp *PublicParameter) LedgerTxoSerialNumberGen(lgrTxo *LgrTxoMLP, coinSerialNumberSecretKey []byte) ([]byte, error) {
	if lgrTxo == nil || lgrTxo.txo == nil || len(lgrTxo.id) == 0 {
		return nil, fmt.Errorf("LedgerTxoSerialNumberGen: there is nil in the input LgrTxoMLP")
	}

	m_r, err := pp.expandKIDRMLP(lgrTxo)
	if err != nil {
		return nil, err
	}

	coinAddressType := lgrTxo.txo.CoinAddressType()

	var ma_p *PolyANTT
	if len(coinSerialNumberSecretKey) != 0 {
		if coinAddressType != CoinAddressTypePublicKeyForRingPre && coinAddressType != CoinAddressTypePublicKeyForRing {
			return nil, fmt.Errorf("LedgerTxoSerialNumberGen: the input coinSerialNumberSecretKey is not nil/empty, while the input lgrTxo's CoinAddressType (%d) is not CoinAddressTypePublicKeyForRingPre or CoinAddressTypePublicKeyForRing", coinAddressType)
		}

		askSn, err := pp.coinSerialNumberSecretKeyForPKRingParse(coinSerialNumberSecretKey)
		if err != nil {
			return nil, err
		}

		ma_p = pp.PolyANTTAdd(askSn.ma, m_r)

	} else {

		if coinAddressType != CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("LedgerTxoSerialNumberGen: the input coinSerialNumberSecretKey is nil/empty, while the input lgrTxo's CoinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		ma_p = m_r
	}

	sn, err := pp.ledgerTxoSerialNumberComputeMLP(ma_p)
	if err != nil {
		return nil, err
	}
	return sn, nil
}

// todo: remove this
//func (pp *PublicParameter) TxoCoinSerialNumberGen(lgrTxo *LgrTxoMLP, coinSerialNumberSecretKey []byte) ([]byte, error) {
//	m_r, err := pp.expandKIDRMLP(lgrTxo)
//	if err != nil {
//		return nil, err
//	}
//
//	askSn, err := pp.coinSerialNumberSecretKeyForPKRingParse(coinSerialNumberSecretKey)
//	ma_ps := pp.PolyANTTAdd(askSn.ma, m_r)
//
//	return pp.ledgerTxoSerialNumberComputeMLP(ma_ps)
//}
