package pqringctx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/pqabelian/pqringctx/pqringctxkem"
	"io"
)

// CtxTxo is used as a component object for CtxCoinbaseTx and CtxTransferTx.
// As the Txos in one CtxCoinbaseTx/CTxTransferTx could have different privacy-levels
// and consequently have different structures,
// here we use an interface to define CtxTxo.
// review done 2025.12.21
type CtxTxo interface {
	CtxTxoType() CtxTxoType
}

// CtxTxoHidden defines the CtxTxo with value-hidden.
// review done 2025.12.21
type CtxTxoHidden struct {
	ctxTxoType      CtxTxoType
	valueCommitment *ValueCommitment
	vct             []byte //	value ciphertext
	ctKemSerialized []byte //  ciphertext for kem
}

// CtxTxoType is the method that all CtxTxo instance shall implement, which returns the ctxTxoType.
// review done 2025.12.21
func (ctxTxoHidden *CtxTxoHidden) CtxTxoType() CtxTxoType {
	return ctxTxoHidden.ctxTxoType
}

// CtxTxoPublic defines the CtxTxo with value-public.
// review done 2025.12.21
type CtxTxoPublic struct {
	ctxTxoType CtxTxoType
	value      uint64
}

// CtxTxoType is the method that all CtxTxo instance shall implement, which returns the ctxTxoType.
// review done 2025.12.21
func (ctxTxoPublic *CtxTxoPublic) CtxTxoType() CtxTxoType {
	return ctxTxoPublic.ctxTxoType
}

//	TXO	Gen		begin
//

// ctxTxoHiddenGen() returns a CtxTxo and the randomness used to generate the commitment.
// review done 2025.12.21
func (pp *PublicParameter) ctxTxoHiddenGen(coinValuePublicKey []byte, value uint64) (ctxTxo *CtxTxoHidden, cmtr *PolyCNTTVec, err error) {

	//	got (C, kappa) from key encapsulate mechanism
	ctKemSerialized, kappa, err := pqringctxkem.Encaps(pp.paramKem, coinValuePublicKey)
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
	//	the vc should have length only N, to prevent the unused D-N bits of leaking information
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
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th, 50th, 49th bits to be their real value.
	//	By this way, we can avoid the leaking the corresponding bits of pad.

	retTxo := &CtxTxoHidden{
		ctxTxoType:      CtxTxoTypeHidden,
		valueCommitment: cmt,
		vct:             vct,
		ctKemSerialized: ctKemSerialized,
	}

	return retTxo, cmtr, nil
}

// ctxTxoPublicGen() returns a CtxTxoPublic.
// review done 2025.12.21
func (pp *PublicParameter) ctxTxoPublicGen(value uint64) (ctxTxo *CtxTxoPublic, err error) {
	return &CtxTxoPublic{
		ctxTxoType: CtxTxoTypePublic,
		value:      value,
	}, nil
}

//	TXO	Gen		end

// ExtractValueAndRandFromCtxTxo extract the (value, randomness, commitment) pair for input CtxTxo.
// review done 2025.12.21
func (pp *PublicParameter) ExtractValueAndRandFromCtxTxo(ctxTxo CtxTxo, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, cmtr *PolyCNTTVec, cmt *ValueCommitment, err error) {

	if !pp.CtxTxoSanityCheck(ctxTxo) {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the input ctxTxo is not well-form")
	}

	var ctKemSerialized []byte
	var vct []byte
	switch txoInst := ctxTxo.(type) {
	case *CtxTxoHidden:

		ctKemSerialized = txoInst.ctKemSerialized
		vct = txoInst.vct
		cmt = txoInst.valueCommitment

	case *CtxTxoPublic:
		return txoInst.value, nil, nil, nil

	default:
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the input ctxTxo is not CtxTxoHidden or CtxTxoPublic")
	}
	// Note that with the previous sanity-check, (ctKemSerialized, vct, valueCommitment) are well-form.

	//	Check the validity of (coinValuePublicKey, coinValueSecretKey)
	if len(coinValuePublicKey) != pqringctxkem.GetKemPublicKeyBytesLen(pp.paramKem) {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the input coinValuePublicKey is not well-form")
	}

	if len(coinValueSecretKey) != pqringctxkem.GetKemSecretKeyBytesLen(pp.paramKem) {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the input coinValueSecretKey is not well-form")
	}

	copiedCoinValueSecretKey := make([]byte, len(coinValueSecretKey))
	copy(copiedCoinValueSecretKey, coinValueSecretKey)
	validValueKey, hints := pp.CoinValueKeyVerify(coinValuePublicKey, copiedCoinValueSecretKey)
	if !validValueKey {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the input (coinValuePublicKey, coinValueSecretKey) is not a valid key pair: %v", hints)
	}
	copy(copiedCoinValueSecretKey, coinValueSecretKey)

	//	decaps to have the K
	kappa, err := pqringctxkem.Decaps(pp.paramKem, ctKemSerialized, copiedCoinValueSecretKey)
	if err != nil {
		return 0, nil, nil, err
	}

	//	decrypt vct to obtain the value
	//	vpt = vct ^ sk
	sk, err := pp.expandValuePadRandomness(kappa)
	if err != nil {
		return 0, nil, nil, err
	}
	if len(sk) != pp.TxoValueBytesLen() {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: the expanded sk for value pad has a wrong length (%d)", len(sk))
	}

	vpt := make([]byte, pp.TxoValueBytesLen())
	for i := 0; i < pp.TxoValueBytesLen(); i++ {
		vpt[i] = vct[i] ^ sk[i]
	}
	vpt[6] = vpt[6] & 0x07
	// This is to make the 56th~52th bit always to be 0, while keeping the 51th, 50th, 49th bits to be their real value.

	value, err = pp.decodeTxoValueFromBytes(vpt)
	if err != nil {
		return 0, nil, nil, err
	}

	//	expand cmtr and open the commitment
	cmtr_poly, err := pp.expandValueCmtRandomness(kappa)
	if err != nil {
		return 0, nil, nil, err
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

	if !pp.PolyCNTTVecEqualCheck(b, cmt.b) || !pp.PolyCNTTEqualCheck(c, cmt.c) {
		return 0, nil, nil, fmt.Errorf("ExtractValueAndRandFromCtxTxo: reject when using the recoverd (value, randomness) to open the commitment")
	}

	return value, cmtr, cmt, nil
}

// GetCtxTxoSerializeSizeByCtxTxoType returns the serialize size of a CtxTxo for the input CtxTxoType.
// review done 2025.12.21
func (pp *PublicParameter) GetCtxTxoSerializeSizeByCtxTxoType(ctxTxoType CtxTxoType) (int, error) {
	switch ctxTxoType {
	case CtxTxoTypeHidden:
		return pp.CtxTxoHiddenSerializeSize(), nil
	case CtxTxoTypePublic:
		return pp.CtxTxoPublicSerializeSize(), nil
	default:
		return 0, fmt.Errorf("GetCtxTxoSerializeSizeByCtxTxoType: unsupported ctxTxoType")
	}
}

// CtxTxoSerializeSize returns the serializedSize for the input CtxTxo.
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoSerializeSize(ctxTxo CtxTxo) (int, error) {
	if ctxTxo == nil {
		return 0, fmt.Errorf("CtxTxoSerializeSize: the input ctxTxo is nil")
	}

	switch ctxTxo.(type) {

	case *CtxTxoHidden:
		if ctxTxo.CtxTxoType() != CtxTxoTypeHidden {
			return 0, fmt.Errorf("CtxTxoSerializeSize: the input ctxTxo is CtxTxoHidden, but the CtxTxoType %d does not match", ctxTxo.CtxTxoType())
		}
		return pp.CtxTxoHiddenSerializeSize(), nil

	case *CtxTxoPublic:
		if ctxTxo.CtxTxoType() != CtxTxoTypePublic {
			return 0, fmt.Errorf("CtxTxoSerializeSize: the input ctxTxo is CtxTxoPublic, but the CtxTxoType %d does not match", ctxTxo.CtxTxoType())
		}
		return pp.CtxTxoPublicSerializeSize(), nil
	default:
		return 0, fmt.Errorf("CtxTxoSerializeSize: the input ctxTxo is not CtxTxoHidden or CtxTxoPublic")
	}
}

// SerializeCtxTxo serializes the input CtxTxo to []byte.
// review done 2025.12.21
func (pp *PublicParameter) SerializeCtxTxo(ctxTxo CtxTxo) (serializedTxo []byte, err error) {
	if ctxTxo == nil {
		return nil, fmt.Errorf("SerializeCtxTxo: the input ctxTxo is nil")
	}

	switch txoInst := ctxTxo.(type) {
	case *CtxTxoHidden:
		if ctxTxo.CtxTxoType() != CtxTxoTypeHidden {
			return nil, fmt.Errorf("SerializeCtxTxo: the input ctxTxo is CtxTxoHidden, but the CtxTxoType %d does not match", ctxTxo.CtxTxoType())
		}
		return pp.serializeCtxTxoHidden(txoInst)

	case *CtxTxoPublic:
		if ctxTxo.CtxTxoType() != CtxTxoTypePublic {
			return nil, fmt.Errorf("SerializeCtxTxo: the input ctxTxo is CtxTxoPublic, but the CtxTxoType %d does not match", ctxTxo.CtxTxoType())
		}
		return pp.serializeCtxTxoPublic(txoInst)
	default:
		return nil, fmt.Errorf("SerializeCtxTxo: the input ctxTxo is not CtxTxoHidden or CtxTxoPublic")
	}
}

// DeserializeCtxTxo deserialize the input []byte to a CtxTxo.
// review done 2025.12.21
func (pp *PublicParameter) DeserializeCtxTxo(serializedTxo []byte) (ctxTxo CtxTxo, err error) {
	if len(serializedTxo) == 0 {
		return nil, fmt.Errorf("DeserializeCtxTxo: the input serializedTxo is empty")
	}

	n := len(serializedTxo)
	if n == pp.CtxTxoHiddenSerializeSize() {
		return pp.deserializeCtxTxoHidden(serializedTxo)
	} else if n == pp.CtxTxoPublicSerializeSize() {
		return pp.deserializeCtxTxoPublic(serializedTxo)
	} else {
		return nil, fmt.Errorf("DeserializeCtxTxo: the input serializedTxo has a length that is not supported")
	}
}

// CtxTxoHiddenSerializeSize returns the serialize size for CtxTxoHidden.
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoHiddenSerializeSize() int {
	ctKemSerializedLen := pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
	return 1 + // for ctxTxoType
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(ctKemSerializedLen)) + ctKemSerializedLen
}

// serializeCtxTxoHidden serialize the input CtxTxoHidden to []byte.
// review done 2025.12.21
func (pp *PublicParameter) serializeCtxTxoHidden(ctxTxoHidden *CtxTxoHidden) ([]byte, error) {

	if !pp.CtxTxoHiddenSanityCheck(ctxTxoHidden) {
		return nil, fmt.Errorf("serializeCtxTxoHidden: the input ctxTxoHidden is not well-form")
	}

	var err error
	length := pp.CtxTxoHiddenSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	// ctxTxoType is fixed-length, say 1 byte
	err = w.WriteByte(byte(ctxTxoHidden.ctxTxoType))
	if err != nil {
		return nil, err
	}

	//	serializedValueCmt is fixed-length
	serializedValueCmt, err := pp.SerializeValueCommitment(ctxTxoHidden.valueCommitment)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedValueCmt)
	if err != nil {
		return nil, err
	}

	//	txo.Vct is fixed-length
	_, err = w.Write(ctxTxoHidden.vct)
	if err != nil {
		return nil, err
	}

	//	txo.CtKemSerialized depends on the KEM, the length is not in the scope of pqringctx.
	err = writeVarBytes(w, ctxTxoHidden.ctKemSerialized)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeCtxTxoHidden deserialize the input []byte to a CtxTxoHidden.
// review done 2025.12.21
func (pp *PublicParameter) deserializeCtxTxoHidden(serializedCtxTxoHidden []byte) (*CtxTxoHidden, error) {
	var err error
	r := bytes.NewReader(serializedCtxTxoHidden)

	var ctxTxoType byte
	ctxTxoType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if CtxTxoType(ctxTxoType) != CtxTxoTypeHidden {
		return nil, fmt.Errorf("deserializeCtxTxoHidden: the deserialized ctxTxoType is not CtxTxoTypeHidden")
	}

	var cmt *ValueCommitment
	tmp := make([]byte, pp.ValueCommitmentSerializeSize())
	// _, err = r.Read(tmp)
	_, err = io.ReadFull(r, tmp)
	if err != nil {
		return nil, err
	}
	cmt, err = pp.DeserializeValueCommitment(tmp)
	if err != nil {
		return nil, err
	}

	vct := make([]byte, pp.TxoValueBytesLen())
	// _, err = r.Read(vct)
	_, err = io.ReadFull(r, vct)
	if err != nil {
		return nil, err
	}

	ctKem, err := readVarBytes(r, MaxAllowedKemCiphertextSize, "CtxTxoHidden.CtKemSerialized")
	if err != nil {
		return nil, err
	}

	return &CtxTxoHidden{
		ctxTxoType:      CtxTxoTypeHidden,
		valueCommitment: cmt,
		vct:             vct,
		ctKemSerialized: ctKem,
	}, nil
}

// CtxTxoPublicSerializeSize returns the serialized size for CtxTxoPublic.
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoPublicSerializeSize() int {
	return 1 + // for ctxTxoType
		8 // for value
}

// serializeCtxTxoPublic serialize the input CtxTxoPublic to []byte.
// review done 2025.12.21
func (pp *PublicParameter) serializeCtxTxoPublic(ctxTxoPublic *CtxTxoPublic) ([]byte, error) {

	if !pp.CtxTxoPublicSanityCheck(ctxTxoPublic) {
		return nil, fmt.Errorf("serializeCtxTxoPublic: the input ctxTxoPublic is not well-form")
	}

	var err error
	length := pp.CtxTxoPublicSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	// ctxTxoPublic.ctxTxoType is fixed-length, say 1 byte
	err = w.WriteByte(byte(ctxTxoPublic.ctxTxoType))
	if err != nil {
		return nil, err
	}

	// ctxTxoPublic.value is fixed-length
	err = binarySerializer.PutUint64(w, binary.LittleEndian, ctxTxoPublic.value)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeCtxTxoPublic deserialize the input []byte to a CtxTxoPublic.
// review done 2025.12.21
func (pp *PublicParameter) deserializeCtxTxoPublic(serializedCtxTxoPublic []byte) (*CtxTxoPublic, error) {
	var err error
	r := bytes.NewReader(serializedCtxTxoPublic)

	var ctxTxoType byte
	ctxTxoType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if CtxTxoType(ctxTxoType) != CtxTxoTypePublic {
		return nil, fmt.Errorf("deserializeCtxTxoPublic: the deserialized ctxTxoType is not CtxTxoTypePublic")
	}

	var value uint64
	value, err = binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	return &CtxTxoPublic{
		ctxTxoType: CtxTxoTypePublic,
		value:      value,
	}, nil

}

// sanity check functions	begin

// CtxTxoSanityCheck conducts sanity-check on the input CtxTxo.
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoSanityCheck(ctxTxo CtxTxo) bool {
	if ctxTxo == nil {
		return false
	}

	switch txoInst := ctxTxo.(type) {
	case *CtxTxoHidden:
		return pp.CtxTxoHiddenSanityCheck(txoInst)

	case *CtxTxoPublic:
		return pp.CtxTxoPublicSanityCheck(txoInst)

	default:
		return false
	}
}

// CtxTxoHiddenSanityCheck checks whether the input CtxTxoHidden is well-from.
// (1) not nil
// (2) ctxTxoHidden.ctxTxoType is correct
// (3) ctxTxoHidden.valueCommitment is well-form
// (4) ctxTxoHidden.vct has correct length
// (5) ctxTxoHidden.ctKemSerialized has correct length.
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoHiddenSanityCheck(ctxTxoHidden *CtxTxoHidden) bool {
	if ctxTxoHidden == nil {
		return false
	}

	if ctxTxoHidden.ctxTxoType != CtxTxoTypeHidden {
		return false
	}

	if !pp.ValueCommitmentSanityCheck(ctxTxoHidden.valueCommitment) {
		return false
	}

	if len(ctxTxoHidden.vct) != pp.TxoValueBytesLen() {
		return false
	}

	if len(ctxTxoHidden.ctKemSerialized) != pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem) {
		return false
	}

	return true
}

// CtxTxoPublicSanityCheck checks whether the input CtxTxoPublic is well-from.
// (1) not nil
// (2) ctxTxoPublic.ctxTxoType is correct
// (3) TxoSDN.value is in the correct scope [1, 2^N-1] (note that CtxTxoPublic.value is public and could not be 0).
// review done 2025.12.21
func (pp *PublicParameter) CtxTxoPublicSanityCheck(ctxTxoPublic *CtxTxoPublic) bool {
	if ctxTxoPublic == nil {
		return false
	}

	if ctxTxoPublic.ctxTxoType != CtxTxoTypePublic {
		return false
	}

	if ctxTxoPublic.value == 0 {
		return false
	}

	if !pp.ValueMaxSanityCheck(ctxTxoPublic.value) {
		return false
	}

	return true
}

// common functions	begin

// ValueMaxSanityCheck checks whether the passed value in the scope [0, 2^N-1].
// review done 2025.12.21
func (pp *PublicParameter) ValueMaxSanityCheck(value uint64) bool {
	V := (uint64(1) << pp.paramN) - 1

	if value > V {
		return false
	}

	return true
}

// common functions	end

// ctx review done 2025.12.21
