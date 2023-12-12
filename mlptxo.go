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

// CoinAddressType is the method that all TxoMLP instance shall implement.
// reviewed on 2023.12.05
func (txoRCTPre *TxoRCTPre) CoinAddressType() CoinAddressType {
	return txoRCTPre.coinAddressType
}

// TxoRCT defines the Txo with RingCT-privacy.
// reviewed on 2023.12.05
type TxoRCT struct {
	coinAddressType         CoinAddressType
	addressPublicKeyForRing *AddressPublicKeyForRing
	valueCommitment         *ValueCommitment
	vct                     []byte //	value ciphertext
	ctKemSerialized         []byte //  ciphertext for kem
}

// CoinAddressType is the method that all TxoMLP instance shall implement.
// reviewed on 2023.12.05
func (txoRCT *TxoRCT) CoinAddressType() CoinAddressType {
	return txoRCT.coinAddressType
}

// TxoSDN defines the Txo with Pseudonym-privacy.
// reviewed on 2023.12.05
type TxoSDN struct {
	coinAddressType               CoinAddressType
	addressPublicKeyForSingleHash []byte
	value                         uint64
}

// CoinAddressType is the method that all TxoMLP instance shall implement.
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
func (pp *PublicParameter) txoRCTPreGen(coinAddress []byte, vpk []byte, value uint64) (txo *TxoRCTPre, cmtr *PolyCNTTVec, err error) {
	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, vpk)
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
func (pp *PublicParameter) txoRCTGen(coinAddress []byte, vpk []byte, value uint64) (txo *TxoRCT, cmtr *PolyCNTTVec, err error) {

	//	got (C, kappa) from key encapsulate mechanism
	// Restore the KEM version
	CtKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, vpk[1:])
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

	addressPublicKeyForRing, err := pp.deserializeAddressPublicKeyForRing(coinAddress[1:])

	retTxo := &TxoRCT{
		CoinAddressTypePublicKeyForRing,
		addressPublicKeyForRing,
		cmt,
		vct,
		CtKemSerialized,
	}

	return retTxo, cmtr, nil
}

// txoSDNGen() returns a transaction output and the randomness used to generate the commitment.
// Note that coinAddress should be 1 byte (CoinAddressType) + AddressPublicKeyForSingleHash.
// reviewed on 2023.12.07
func (pp *PublicParameter) txoSDNGen(coinAddress []byte, value uint64) (txo *TxoSDN) {
	return &TxoSDN{
		CoinAddressTypePublicKeyHashForSingle,
		coinAddress[1:],
		value,
	}
}

//	TXO	Gen		end

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
// reviewed on 2023.12.04
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
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
// review on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) TxoRCTPreSerializeSize() int {
	return pp.addressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

// serializeTxoRCTPre serialize the input TxoRCTPre into []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
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
func (pp *PublicParameter) TxoRCTSerializeSize() int {
	return 1 + // for coinAddressType
		pp.addressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

// serializeTxoRCT serialize the input TxoRCT to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
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
		cmt,
		vct,
		ctKem}, nil
}

// TxoSDNSerializeSize returns the serialized size for TxoSDN.
// review on 2023.12.04.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
func (pp *PublicParameter) TxoSDNSerializeSize() int {
	return 1 + // for coinAddressType
		HashOutputBytesLen + //	for addressPublicKeyForSingleHash
		8 // for value
}

// serializeTxoSDN serialize the input TxoSDN to []byte.
// reviewed on 2023.12.05.
// reviewed on 2023.12.07
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

	var value uint64
	value, err = binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	return &TxoSDN{
		CoinAddressTypePublicKeyHashForSingle,
		apkHash,
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
