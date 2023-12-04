package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxkem"
)

func (pp *PublicParameter) GetNullSerialNumber() []byte {
	snSize := pp.ledgerTxoSerialNumberSerializeSize()
	nullSn := make([]byte, snSize)
	for i := 0; i < snSize; i++ {
		nullSn[i] = 0
	}
	return nullSn
}

// Txo Serialization	begin
func (pp *PublicParameter) GetTxoMLPSerializeSize(coinAddressType CoinAddressType) (int, error) {
	switch coinAddressType {
	case CoinAddressTypePublicKeyForRingPre:
		return pp.TxoRCTPreSerializeSize(), nil
	case CoinAddressTypePublicKeyForRing:
		return pp.TxoRCTSerializeSize(), nil
	case CoinAddressTypePublicKeyHashForSingle:
		return pp.TxoSDNSerializeSize(), nil
	default:
		return 0, errors.New("TxoMLPSerializeSize: unsupported coinAddressType")
	}
}

// TxoMLPSerializeSize returns the serializedSize for the input TxoMLP.
// reviewed on 2023.12.04
func (pp *PublicParameter) TxoMLPSerializeSize(txoMLP TxoMLP) (int, error) {
	if txoMLP == nil {
		return 0, errors.New("TxoMLPSerializeSize: the input TxoMLP is nil")
	}

	switch txoMLP.(type) {
	case *TxoRCTPre:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRingPre {
			errStr := fmt.Sprintf("TxoMLPSerializeSize: the input TxoMLP is TxoRCTPre, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return 0, errors.New(errStr)
		}
		return pp.TxoRCTPreSerializeSize(), nil

	case *TxoRCT:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRing {
			errStr := fmt.Sprintf("TxoMLPSerializeSize: the input TxoMLP is TxoRCT, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return 0, errors.New(errStr)
		}
		return pp.TxoRCTSerializeSize(), nil

	case *TxoSDN:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyHashForSingle {
			errStr := fmt.Sprintf("TxoMLPSerializeSize: the input TxoMLP is TxoSDN, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return 0, errors.New(errStr)
		}
		return pp.TxoSDNSerializeSize(), nil
	default:
		return 0, errors.New("TxoMLPSerializeSize: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

func (pp *PublicParameter) SerializeTxoMLP(txoMLP TxoMLP) (serializedTxo []byte, err error) {
	if txoMLP == nil {
		return nil, errors.New("SerializeTxoMLP: the input TxoMLP is nil")
	}

	switch txoInst := txoMLP.(type) {
	case *TxoRCTPre:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRingPre {
			errStr := fmt.Sprintf("SerializeTxoMLP: the input TxoMLP is TxoRCTPre, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxoRCTPre(txoInst)

	case *TxoRCT:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyForRing {
			errStr := fmt.Sprintf("SerializeTxoMLP: the input TxoMLP is TxoRCT, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxoRCT(txoInst)

	case *TxoSDN:
		if txoMLP.CoinAddressType() != CoinAddressTypePublicKeyHashForSingle {
			errStr := fmt.Sprintf("SerializeTxoMLP: the input TxoMLP is TxoSDN, but the CoinAddressType %d does not match", txoMLP.CoinAddressType())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxoSDN(txoInst)
	default:
		return nil, errors.New("SerializeTxoMLP: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

func (pp *PublicParameter) DeserializeTxoMLP(serializedTxo []byte) (txoMLP TxoMLP, err error) {
	if serializedTxo == nil {
		return nil, errors.New("DeserializeTxoMLP: the input serializedTxo is nil")
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
func (pp *PublicParameter) TxoRCTPreSerializeSize() int {
	return pp.AddressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

func (pp *PublicParameter) serializeTxoRCTPre(txoRCTPre *TxoRCTPre) ([]byte, error) {
	if txoRCTPre == nil || txoRCTPre.addressPublicKeyForRing == nil || txoRCTPre.valueCommitment == nil {
		return nil, errors.New("serializeTxoRCTPre: there is nil pointer in the input txoRCTPre")
	}

	var err error
	length := pp.TxoRCTPreSerializeSize()
	w := bytes.NewBuffer(make([]byte, 0, length))

	//	serializedAddressPublicKey is fixed-length
	serializedAddressPublicKeyForRing, err := pp.SerializeAddressPublicKeyForRing(txoRCTPre.addressPublicKeyForRing)
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

func (pp *PublicParameter) deserializeTxoRCTPre(serializedTxoRCTPre []byte) (*TxoRCTPre, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCTPre)

	var apk *AddressPublicKeyForRing
	tmp := make([]byte, pp.AddressPublicKeyForRingSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	apk, err = pp.DeserializeAddressPublicKeyForRing(tmp)
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

// TxoRCTSerializeSize returns the serialized size for TxoRCT.
// review on 2023.12.04.
func (pp *PublicParameter) TxoRCTSerializeSize() int {
	return 1 + // for coinAddressType
		pp.AddressPublicKeyForRingSerializeSize() +
		pp.ValueCommitmentSerializeSize() +
		pp.TxoValueBytesLen() +
		VarIntSerializeSize(uint64(pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem))) + pqringctxkem.GetKemCiphertextBytesLen(pp.paramKem)
}

func (pp *PublicParameter) serializeTxoRCT(txoRCT *TxoRCT) ([]byte, error) {
	if txoRCT == nil || txoRCT.addressPublicKeyForRing == nil || txoRCT.valueCommitment == nil {
		return nil, errors.New("serializeTxoRCT: there is nil pointer in the input txoRCT")
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
	serializedAddressPublicKeyForRing, err := pp.SerializeAddressPublicKeyForRing(txoRCT.addressPublicKeyForRing)
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

func (pp *PublicParameter) deserializeTxoRCT(serializedTxoRCT []byte) (*TxoRCT, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCT)

	var coinAddressType byte
	coinAddressType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if coinAddressType != byte(CoinAddressTypePublicKeyForRing) {
		return nil, errors.New("deserializeTxoRCT: the deserialized coinAddressType is not CoinAddressTypePublicKeyForRing")
	}

	var apk *AddressPublicKeyForRing
	tmp := make([]byte, pp.AddressPublicKeyForRingSerializeSize())
	_, err = r.Read(tmp)
	if err != nil {
		return nil, err
	}
	apk, err = pp.DeserializeAddressPublicKeyForRing(tmp)
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
func (pp *PublicParameter) TxoSDNSerializeSize() int {
	return 1 + // for coinAddressType
		HashOutputBytesLen + //	for addressPublicKeyForSingleHash
		8 // for value
}

func (pp *PublicParameter) serializeTxoSDN(txoSDN *TxoSDN) ([]byte, error) {
	if txoSDN == nil || txoSDN.addressPublicKeyForSingleHash == nil {
		return nil, errors.New("serializeTxoSDN: there is nil pointer in the input txoSDN")
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

func (pp *PublicParameter) deserializeTxoSDN(serializedTxoRCT []byte) (*TxoSDN, error) {
	var err error
	r := bytes.NewReader(serializedTxoRCT)

	var coinAddressType byte
	coinAddressType, err = r.ReadByte()
	if err != nil {
		return nil, err
	}
	if coinAddressType != byte(CoinAddressTypePublicKeyHashForSingle) {
		return nil, errors.New("deserializeTxoSDN: the deserialized coinAddressType is not CoinAddressTypePublicKeyHashForSingle")
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

//	Txo Serialization	end

// TxWitness Serialization	begin

// todo
func (pp *PublicParameter) TxWitnessMLPSerializeSizeByDesc() (int, error) {
	return 0, nil
}

// TxWitnessMLPSerializeSize returns the serialized size for the input TxWitnessMLP.
// reviewed on 2023.12.04 todo
func (pp *PublicParameter) TxWitnessMLPSerializeSize(txWitnessMLP TxWitnessMLP) (int, error) {
	if txWitnessMLP == nil {
		return 0, errors.New("TxWitnessMLPSerializeSize: the input txWitnessMLP is nil")
	}

	switch txWitnessInst := txWitnessMLP.(type) {
	case *TxWitnessCbTxI0C0:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0C0 {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0C0, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0C0SerializeSize(), nil

	case *TxWitnessCbTxI0C1:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0C1 {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0C1, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0C1SerializeSize(), nil

	case *TxWitnessCbTxI0Cn:
		if txWitnessMLP.TxCase() != TxCaseCbTxI0Cn {
			errStr := fmt.Sprintf("TxWitnessMLPSerializeSize: the input txWitnessMLP is TxWitnessCbTxI0Cn, but the TxCase %d does not match", txWitnessMLP.TxCase())
			return 0, errors.New(errStr)
		}
		return pp.TxWitnessCbTxI0CnSerializeSize(txWitnessInst.balanceProof.RightCommNum()), nil

		// todo: more cases

	default:
		return 0, errors.New("TxoMLPSerializeSize: the input TxoMLP is not TxoRCTPre, TxoRCT, TxoSDN")
	}
}

// todo(MLP): to finish and review, 2023.12.04
func (pp *PublicParameter) SerializeTxWitnessMLP(txWitnessMLP TxWitnessMLP) (serializedTxWitness []byte, err error) {
	if txWitnessMLP == nil {
		return nil, errors.New("SerializeTxWitness: the input TxWitnessMLP is nil")
	}

	switch txWitnessInst := txWitnessMLP.(type) {
	case *TxWitnessCbTxI0C0:
		if txWitnessInst.TxCase() != TxCaseCbTxI0C0 {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0C0, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0C0(txWitnessInst)

	case *TxWitnessCbTxI0C1:
		if txWitnessInst.TxCase() != TxCaseCbTxI0C1 {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0C1, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0C1(txWitnessInst)

	case *TxWitnessCbTxI0Cn:
		if txWitnessInst.TxCase() != TxCaseCbTxI0Cn {
			errStr := fmt.Sprintf("SerializeTxWitness: the input TxWitnessMLP is TxWitnessCbTxI0Cn, but the TxCase %d does not match", txWitnessInst.TxCase())
			return nil, errors.New(errStr)
		}
		return pp.serializeTxWitnessCbTxI0Cn(txWitnessInst)

		// todo(MLP): more cases

	default:
		return nil, errors.New("SerializeTxWitness: the input TxWitnessMLP is not in the supported TxCases")
	}
}

func (pp *PublicParameter) extractTxCaseFromSerializedTxWitnessMLP(serializedTxWitness []byte) (TxCase, error) {
	if len(serializedTxWitness) <= 0 {
		return 0, errors.New("extractTxCaseFromSerializedTxWitnessMLP: the input serializedTxWitness is nil or empty")
	}

	txCase := TxCase(serializedTxWitness[0])

	return txCase, nil

}

func (pp *PublicParameter) DeserializeTxWitnessMLP(serializedTxWitness []byte) (txWitnessMLP TxWitnessMLP, err error) {
	n := len(serializedTxWitness)

	if n <= 0 {
		return nil, errors.New("DeserializeTxWitnessMLP: the input serializedTxWitness is nil or empty")
	}

	txCase, err := pp.extractTxCaseFromSerializedTxWitnessMLP(serializedTxWitness)
	if err != nil {
		return nil, err
	}

	switch txCase {
	case TxCaseCbTxI0C0:
		return pp.deserializeTxWitnessCbTxI0C0(serializedTxWitness)
	case TxCaseCbTxI0C1:
		return pp.deserializeTxWitnessCbTxI0C1(serializedTxWitness)
	case TxCaseCbTxI0Cn:
		return pp.deserializeTxWitnessCbTxI0C2(serializedTxWitness)
	default:
		return nil, errors.New("DeserializeTxWitnessMLP: the input serializedTxWitness has a TxCase that is not supported")
	}
}

// TxWitnessCbTxI0C0SerializeSize returns the serialized size for TxWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) TxWitnessCbTxI0C0SerializeSize() int {
	// TxWitnessCbTxI0C0 actually does not contain any witness, and only contain its TxCase.
	return 1
}

// serializeTxWitnessCbTxI0C0 serializes the input txWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) serializeTxWitnessCbTxI0C0(txWitnessCbTxI0C0 *TxWitnessCbTxI0C0) ([]byte, error) {
	if txWitnessCbTxI0C0 == nil {
		return nil, errors.New("serializeTxWitnessCbTxI0C0: the input txWitnessCbTxI0C0 is nil")
	}

	if txWitnessCbTxI0C0.txCase != TxCaseCbTxI0C0 {
		return nil, fmt.Errorf("serializeTxWitnessCbTxI0C0: the TxCase of input txWitnessCbTxI0C0 is %d rather than the expected TxCaseCbTxI0C0 (%d)", txWitnessCbTxI0C0.txCase, TxCaseCbTxI0C0)
	}

	w := bytes.NewBuffer(make([]byte, 0, 1))

	// txWitnessCbTxI0C0.txCase is fixed-length, say 1 byte
	err := w.WriteByte(byte(txWitnessCbTxI0C0.txCase))
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxWitnessCbTxI0C0 deserializes the input []byte to a txWitnessCbTxI0C0.
// reviewed on 2023.12.04
func (pp *PublicParameter) deserializeTxWitnessCbTxI0C0(serializedTxWitnessCbTxI0C0 []byte) (*TxWitnessCbTxI0C0, error) {
	r := bytes.NewReader(serializedTxWitnessCbTxI0C0)

	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if txCase != byte(TxCaseCbTxI0C0) {
		return nil, errors.New("deserializeTxWitnessCbTxI0C0: the deserialized TxCase is not TxCaseCbTxI0C0")
	}

	return &TxWitnessCbTxI0C0{
		txCase: TxCaseCbTxI0C0,
	}, nil
}

// TxWitnessCbTxI0C1SerializeSize returns the serilaized size for TxWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) TxWitnessCbTxI0C1SerializeSize() int {
	n := 1 + //	txCase       TxCase
		pp.balanceProofL0R1SerializedSize() //	balanceProof *balanceProofL0R1
	return n
}

// serializeTxWitnessCbTxI0C1 serialize the input txWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) serializeTxWitnessCbTxI0C1(txWitnessCbTxI0C1 *TxWitnessCbTxI0C1) ([]byte, error) {
	if txWitnessCbTxI0C1 == nil {
		return nil, errors.New("serializeTxWitnessCbTxI0C1: the input txWitnessCbTxI0C1 is nil")
	}

	if txWitnessCbTxI0C1.txCase != TxCaseCbTxI0C1 {
		return nil, fmt.Errorf("serializeTxWitnessCbTxI0C1: the TxCase of input txWitnessCbTxI0C1 is %d rather than the expected TxCaseCbTxI0C0 (%d)", txWitnessCbTxI0C1.txCase, TxCaseCbTxI0C1)
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.TxWitnessCbTxI0C1SerializeSize()))

	// txWitnessCbTxI0C0.txCase is fixed-length, say 1 byte
	err := w.WriteByte(byte(txWitnessCbTxI0C1.txCase))
	if err != nil {
		return nil, err
	}

	//  balanceProof *balanceProofL0R1
	serializedBpf, err := pp.serializeBalanceProofL0R1(txWitnessCbTxI0C1.balanceProof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedBpf)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeTxWitnessCbTxI0C1 deserialize the input serializedTxWitnessCbTxI0C1 into a txWitnessCbTxI0C1.
// Finished and reviewed on 2023.12.04.
func (pp *PublicParameter) deserializeTxWitnessCbTxI0C1(serializedTxWitnessCbTxI0C1 []byte) (*TxWitnessCbTxI0C1, error) {
	r := bytes.NewReader(serializedTxWitnessCbTxI0C1)

	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if txCase != byte(TxCaseCbTxI0C1) {
		return nil, errors.New("deserializeTxWitnessCbTxI0C1: the deserialized TxCase is not TxCaseCbTxI0C1")
	}

	serializedBpf := make([]byte, pp.balanceProofL0R1SerializedSize())
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	bpf, err := pp.deserializeBalanceProofL0R1(serializedBpf)
	if err != nil {
		return nil, err
	}

	return &TxWitnessCbTxI0C1{
		txCase:       TxCaseCbTxI0C1,
		balanceProof: bpf,
	}, nil
}

// todo
func (pp *PublicParameter) TxWitnessCbTxI0CnSerializeSize(outForRing uint8) int {
	n := 1 + //	txCase       TxCase
		pp.balanceProofLmRnSerializedSizeByCommNum(0, outForRing) //	balanceProof *balanceProofLmRn
	return n
}

func (pp *PublicParameter) serializeTxWitnessCbTxI0Cn(txWitnessCbTxI0C2 *TxWitnessCbTxI0Cn) ([]byte, error) {
	return nil, nil
}
func (pp *PublicParameter) deserializeTxWitnessCbTxI0C2(serializedTxWitnessCbTxI0C2 []byte) (*TxWitnessCbTxI0Cn, error) {
	return nil, nil
}

//	TxWitness Serialization	end

// Tx Serialization	begin

// CoinbaseTxMLPSerializeSize compute the serializedSize for CoinbaseTxMLP.
// reviewed on 2023.12.04
func (pp *PublicParameter) CoinbaseTxMLPSerializeSize(tx *CoinbaseTxMLP, withWitness bool) (int, error) {
	var length int

	// Vin uint64
	length = 8

	//txos []*txoMLP
	length += VarIntSerializeSize(uint64(len(tx.txos)))
	for i := 0; i < len(tx.txos); i++ {
		txoLen, err := pp.TxoMLPSerializeSize(tx.txos[i])
		if err != nil {
			return 0, nil
		}
		length += VarIntSerializeSize(uint64(txoLen)) + txoLen
	}

	//TxMemo []byte
	length += VarIntSerializeSize(uint64(len(tx.txMemo))) + len(tx.txMemo)

	// TxWitness
	if withWitness {
		witnessLen, err := pp.TxWitnessMLPSerializeSize(tx.txWitness)
		if err != nil {
			return 0, err
		}
		length += VarIntSerializeSize(uint64(witnessLen)) + witnessLen
	}

	return length, nil
}

func (pp *PublicParameter) SerializeCoinbaseTxMLP(tx *CoinbaseTxMLP, withWitness bool) ([]byte, error) {
	if tx == nil || len(tx.txos) == 0 {
		return nil, errors.New("SerializeCoinbaseTxMLP: there is nil pointer in CoinbaseTx")
	}

	length, err := pp.CoinbaseTxMLPSerializeSize(tx, withWitness)
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, length))

	// Vin     uint64
	binarySerializer.PutUint64(w, binary.LittleEndian, tx.vin)

	//txos []*txo
	err = WriteVarInt(w, uint64(len(tx.txos)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(tx.txos); i++ {
		serializedTxo, err := pp.SerializeTxoMLP(tx.txos[i])
		if err != nil {
			return nil, err
		}
		err = writeVarBytes(w, serializedTxo)
		if err != nil {
			return nil, err
		}
	}

	//TxMemo []byte
	err = writeVarBytes(w, tx.txMemo)
	if err != nil {
		return nil, err
	}

	if withWitness {

		serializedTxWitness, err := pp.SerializeTxWitnessMLP(tx.txWitness)
		if err != nil {
			return nil, err
		}

		err = writeVarBytes(w, serializedTxWitness)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

//	Tx Serialization	end
