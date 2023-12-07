package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
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

func (pp *PublicParameter) DeserializeTxoMLP(serializedTxo []byte) (txoMLP TxoMLP, err error) {
	if serializedTxo == nil {
		return nil, fmt.Errorf("DeserializeTxoMLP: the input serializedTxo is nil")
	}
	n := len(serializedTxo)
	if n == pp.TxoRCTPreSerializeSize() {
		return pp.deserializeTxoRCTPre(serializedTxo)
	} else if n == pp.TxoRCTSerializeSize() {
		return pp.deserializeTxoRCT(serializedTxo)
	} else if n == pp.TxoSDNSerializeSize() {
		return pp.deserializeTxoSDN(serializedTxo)
	} else {
		return nil, errors.New("DeserializeTxoMLP: the input serializedTxo has a length that is not supported")
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
func (pp *PublicParameter) deserializeTxoRCT(serializedTxoRCT []byte) (*TxoRCT, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCT)

	var coinAddressType byte
	coinAddressType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if CoinAddressType(coinAddressType) != CoinAddressTypePublicKeyForRing {
		return nil, errors.New("deserializeTxoRCT: the deserialized coinAddressType is not CoinAddressTypePublicKeyForRing")
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
