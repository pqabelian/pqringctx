package pqringctx

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// TxWitnessCbTxCase defines the TxCase which will be used to characterize the TxWitnessCbTx.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.05
type TxWitnessCbTxCase uint8

// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.05
const (
	TxWitnessCbTxCaseC0 TxWitnessCbTxCase = 0
	TxWitnessCbTxCaseC1 TxWitnessCbTxCase = 1
	TxWitnessCbTxCaseCn TxWitnessCbTxCase = 2
)

// TxWitnessTrTxCase defines the TxCase which will be used to characterize the TxWitnessTrTx.
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
type TxWitnessTrTxCase uint8

// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
const (
	TxWitnessTrTxCaseI0C0      TxWitnessTrTxCase = 0
	TxWitnessTrTxCaseI0C1      TxWitnessTrTxCase = 1
	TxWitnessTrTxCaseI0Cn      TxWitnessTrTxCase = 2
	TxWitnessTrTxCaseI1C0      TxWitnessTrTxCase = 3
	TxWitnessTrTxCaseI1C1Exact TxWitnessTrTxCase = 4
	TxWitnessTrTxCaseI1C1CAdd  TxWitnessTrTxCase = 5
	TxWitnessTrTxCaseI1C1IAdd  TxWitnessTrTxCase = 6
	TxWitnessTrTxCaseI1CnExact TxWitnessTrTxCase = 7
	TxWitnessTrTxCaseI1CnCAdd  TxWitnessTrTxCase = 8
	TxWitnessTrTxCaseI1CnIAdd  TxWitnessTrTxCase = 9
	TxWitnessTrTxCaseImC0      TxWitnessTrTxCase = 10
	TxWitnessTrTxCaseImC1Exact TxWitnessTrTxCase = 11
	TxWitnessTrTxCaseImC1CAdd  TxWitnessTrTxCase = 12
	TxWitnessTrTxCaseImC1IAdd  TxWitnessTrTxCase = 13
	TxWitnessTrTxCaseImCnExact TxWitnessTrTxCase = 14
	TxWitnessTrTxCaseImCnCAdd  TxWitnessTrTxCase = 15
	TxWitnessTrTxCaseImCnIAdd  TxWitnessTrTxCase = 16
)

// TxWitnessCbTx defines the TxWitness for coinbase-transaction.
// vL = vin - sum of (public value on output side), it must be >= 0.
// Note that with (outForRing),
// we can deterministically decide txCase and balanceProof's case,
// as well as the rpulp case of the balanceProof (if it has, say BalanceProofLmRnGeneral).
// reviewed on 2023.12.07
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
type TxWitnessCbTx struct {
	txCase       TxWitnessCbTxCase
	vL           uint64
	outForRing   uint8
	outForSingle uint8
	//	bpf
	balanceProof BalanceProof
}

// TxCase returns TxWitnessCbTx.txCase.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.05
func (txWitness *TxWitnessCbTx) TxCase() TxWitnessCbTxCase {
	return txWitness.txCase
}

// TxWitnessTrTx defines the TxWitness for Transfer-transaction.
// vPub = sum of (public value on output side) + fee - sum of (public value on input side).
// vPub captures that in TrTX, normally, we have
// cmtIn_1 + ... + cmtIn_m + sum of (public value on input side) = cmtOut_1 + ... + cmtOut_n + sum of (public value on output side) + fee,
// i.e., cmtIn_1 + ... + cmtIn_m = cmtOut_1 + ... + cmtOut_n + vPub.
// If vPub > 0, we will set "(left=in, right=out)".
// If vPub < 0, we will set "(left=out, right=in)".
// If vPub = 0, we will set "(left, right)" based on the number of (m,n).
// Such a setting, will guarantee that when vPub != 0, we will always have
// cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where vRPub > 0.
// Note that with (inForRing, inForSingle, inForSingleDistinct, outForRing, outForSingle, vPub),
// we can deterministically decide txCase and balanceProof's case,
// as well as the rpulp case of the balanceProof (if it has, say BalanceProofLmRnGeneral).
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
type TxWitnessTrTx struct {
	txCase              TxWitnessTrTxCase
	inForRing           uint8
	inForSingle         uint8
	inForSingleDistinct uint8
	inRingSizes         []uint8 // length inForRing
	outForRing          uint8
	outForSingle        uint8
	vPublic             int64
	//	abf
	ma_ps                      []*PolyANTT                  // length inForRing, each for one RingCT-privacy Input. The key-image of the signing key, and is the pre-image of SerialNumber.
	cmts_in_p                  []*ValueCommitment           // length inForRing, each for one RingCT-privacy Input. It commits the same value as the consumed TxoMLP.
	elrSigs                    []*ElrSignatureMLP           // length inForRing, each for one RingCT-privacy Input.
	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	simpleSigs                 []*SimpleSignatureMLP        // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	balanceProof               BalanceProof
}

// TxCase returns the txCase of TxWitnessTrTx.
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (txWitness *TxWitnessTrTx) TxCase() TxWitnessTrTxCase {
	return txWitness.txCase
}

// TxWitnessCbTx	begin

// TxWitnessCbTxSerializeSize returns the serialized size for the input TxWitnessCbTx.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) TxWitnessCbTxSerializeSize(outForRing uint8) (int, error) {
	length := 1 + // txCase       TxWitnessCbTxCase
		8 + //	vL           uint64
		1 + //	outForRing   uint8
		1 //	outForSingle uint8

	//	 balanceProof BalanceProof
	serializedBpfLen, err := pp.balanceProofCbTxSerializeSize(outForRing)
	if err != nil {
		return 0, err
	}
	length = length + VarIntSerializeSize(uint64(serializedBpfLen)) + serializedBpfLen

	return length, nil
}

// SerializeTxWitnessCbTx serialize the input TxWitnessCbTx to []byte.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) SerializeTxWitnessCbTx(txWitness *TxWitnessCbTx) (serializedTxWitness []byte, err error) {

	if !pp.TxWitnessCbTxSanityCheck(txWitness) {
		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx is not well-form")
	}

	length, err := pp.TxWitnessCbTxSerializeSize(txWitness.outForRing)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	// txCase       TxWitnessCbTxCase
	err = w.WriteByte(byte(txWitness.txCase))
	if err != nil {
		return nil, err
	}

	// vL           uint64
	err = binarySerializer.PutUint64(w, littleEndian, txWitness.vL)
	if err != nil {
		return nil, err
	}

	// outForRing   uint8
	err = w.WriteByte(txWitness.outForRing)
	if err != nil {
		return nil, err
	}

	// outForSingle uint8
	err = w.WriteByte(txWitness.outForSingle)
	if err != nil {
		return nil, err
	}

	//	balanceProof               BalanceProof
	serializedBpf, err := pp.serializeBalanceProof(txWitness.balanceProof)
	if err != nil {
		return nil, err
	}
	// we did not use writeVarBytes(), to avoid define the maxAllowLength used in readVarBytes().
	// But for safety and robustness, we serialize the length of serializedBpf.
	bpfLen := len(serializedBpf)
	err = WriteVarInt(w, uint64(bpfLen))
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedBpf) //	here we use fixed-length, since in the deserialization, we can call pp.balanceProofCbTxSerializeSize() to get the balance proof size.
	if err != nil {
		return nil, err
	}

	// an assert, could be removed when test is finished
	serializedBpfExpectedLen, err := pp.balanceProofCbTxSerializeSize(txWitness.outForRing)
	if err != nil {
		return nil, err
	}
	if len(serializedBpf) != serializedBpfExpectedLen {
		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the length of serializedBpfExpectedLen is not the same as expected")
	}

	return w.Bytes(), nil
}

// DeserializeTxWitnessCbTx deserialize the input []byte to TxWitnessCbTx.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed on 2023.12.30
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) DeserializeTxWitnessCbTx(serializedTxWitness []byte) (txWitness *TxWitnessCbTx, err error) {
	if len(serializedTxWitness) == 0 {
		return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the input serializedTxWitness is empty")
	}

	r := bytes.NewReader(serializedTxWitness)

	// txCase       TxWitnessCbTxCase
	var txCase byte
	txCase, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	// vL           uint64
	var vL uint64
	vL, err = binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return nil, err
	}

	// outForRing   uint8
	var outForRing uint8
	outForRing, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	// outForSingle uint8
	var outForSingle uint8
	outForSingle, err = r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	balanceProof BalanceProof
	bpfLen, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	serializedBpfLen, err := pp.balanceProofCbTxSerializeSize(outForRing)
	if err != nil {
		return nil, err
	}
	if uint64(serializedBpfLen) != bpfLen {
		//	This is to check the length. Actually, we can remove this check, and directly use bpfLen.
		return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized bpfLen (%v) does not match with the length (%v) implied by the deserialized outForRing (%d)",
			bpfLen, serializedBpfLen, outForRing)
	}

	serializedBpf := make([]byte, serializedBpfLen)
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	balanceProof, err := pp.deserializeBalanceProof(serializedBpf)
	if err != nil {
		return nil, err
	}

	txWitnessCbTx := &TxWitnessCbTx{
		txCase:       TxWitnessCbTxCase(txCase),
		vL:           vL,
		outForRing:   outForRing,
		outForSingle: outForSingle,
		balanceProof: balanceProof,
	}

	if !pp.TxWitnessCbTxSanityCheck(txWitnessCbTx) {
		return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialzed TxWitnessCbTx is not well-form")
	}

	return txWitnessCbTx, nil

}

//	TxWitnessCbTx	end

// TxWitnessTrTx	begin

// TxWitnessTrTxSerializeSize returns the serialize size for TxWitnessTrTx.
// reviewed on 2023.12.19
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) TxWitnessTrTxSerializeSize(inForRing uint8, inForSingleDistinct uint8,
	outForRing uint8, inRingSizes []uint8, vPublic int64) (int, error) {

	if len(inRingSizes) != int(inForRing) {
		return 0, fmt.Errorf("TxWitnessTrTxSerializeSize: the length of ringSizes[] (%d) is differnet from inForRing (%d)", len(inRingSizes), inForRing)
	}

	length := 1 + //	txCase                     TxWitnessTrTxCase
		3 + //	inForRing uint8, inForSingle uint8, inForSingleDistinct uint8,
		int(inForRing)*1 + // inRingSizes                []uint8
		2 + // outForRing uint8, outForSingle uint8
		8 + //	vPublic                    int64
		int(inForRing)*pp.PolyANTTSerializeSize() + //	ma_ps                      []*PolyANTT
		int(inForRing)*pp.ValueCommitmentSerializeSize() //	cmts_in_p                  []*ValueCommitment

	//	elrSigs                    []*ElrSignatureMLP
	for i := 0; i < int(inForRing); i++ {
		elrSigSize := pp.elrSignatureMLPSerializeSize(inRingSizes[i])
		length = length + elrSigSize
	}

	//	addressPublicKeyForSingles []*AddressPublicKeyForSingle
	length = length + int(inForSingleDistinct)*pp.addressPublicKeyForSingleSerializeSize()

	//	simpleSigs                 []*SimpleSignatureMLP
	length = length + int(inForSingleDistinct)*pp.simpleSignatureSerializeSize()

	//	balanceProof               BalanceProof
	serializedBpfLen, err := pp.balanceProofTrTxSerializeSize(inForRing, outForRing, vPublic)
	if err != nil {
		return 0, err
	}
	length = length + VarIntSerializeSize(uint64(serializedBpfLen)) + serializedBpfLen

	return length, err
}

// SerializeTxWitnessTrTx serialize TxWitnessTrTx to []byte.
// reviewed on 2023.12.19
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.06
func (pp *PublicParameter) SerializeTxWitnessTrTx(txWitness *TxWitnessTrTx) (serializedTxWitness []byte, err error) {

	if !pp.TxWitnessTrTxSanityCheck(txWitness) {
		return nil, fmt.Errorf("SerializeTxWitnessTrTx: the input txWitness *TxWitnessTrTx is not well-form")
	}

	length, err := pp.TxWitnessTrTxSerializeSize(txWitness.inForRing, txWitness.inForSingleDistinct, txWitness.outForRing, txWitness.inRingSizes, txWitness.vPublic)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	//	txCase                     TxWitnessTrTxCase
	err = w.WriteByte(byte(txWitness.txCase))
	if err != nil {
		return nil, err
	}

	//	inForRing                  uint8
	err = w.WriteByte(txWitness.inForRing)
	if err != nil {
		return nil, err
	}

	//	inForSingle                uint8
	err = w.WriteByte(txWitness.inForSingle)
	if err != nil {
		return nil, err
	}

	//	inForSingleDistinct        uint8
	err = w.WriteByte(txWitness.inForSingleDistinct)
	if err != nil {
		return nil, err
	}

	//	inRingSizes                []uint8
	for i := uint8(0); i < txWitness.inForRing; i++ {
		err = w.WriteByte(txWitness.inRingSizes[i])
		if err != nil {
			return nil, err
		}
	}

	//	outForRing                 uint8
	err = w.WriteByte(txWitness.outForRing)
	if err != nil {
		return nil, err
	}

	//	outForSingle               uint8
	err = w.WriteByte(txWitness.outForSingle)
	if err != nil {
		return nil, err
	}

	//	vPublic                    int64
	err = binarySerializer.PutUint64(w, littleEndian, uint64(txWitness.vPublic))
	if err != nil {
		return nil, err
	}

	//	ma_ps                      []*PolyANTT
	for i := uint8(0); i < txWitness.inForRing; i++ {
		err = pp.writePolyANTT(w, txWitness.ma_ps[i])
		if err != nil {
			return nil, err
		}
	}

	//	cmts_in_p                  []*ValueCommitment
	for i := uint8(0); i < txWitness.inForRing; i++ {
		serializedCmt, err := pp.SerializeValueCommitment(txWitness.cmts_in_p[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedCmt)
		if err != nil {
			return nil, err
		}
	}

	//	elrSigs                    []*ElrSignatureMLP
	for i := uint8(0); i < txWitness.inForRing; i++ {
		serializedElrSig, err := pp.serializeElrSignatureMLP(txWitness.elrSigs[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedElrSig)
		if err != nil {
			return nil, err
		}
	}

	//	addressPublicKeyForSingles []*AddressPublicKeyForSingle
	for i := uint8(0); i < txWitness.inForSingleDistinct; i++ {
		serializedApk, err := pp.serializeAddressPublicKeyForSingle(txWitness.addressPublicKeyForSingles[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedApk)
		if err != nil {
			return nil, err
		}
	}

	//	simpleSigs                 []*SimpleSignatureMLP
	for i := uint8(0); i < txWitness.inForSingleDistinct; i++ {
		serializedSimpleSig, err := pp.serializeSimpleSignature(txWitness.simpleSigs[i])
		if err != nil {
			return nil, err
		}
		_, err = w.Write(serializedSimpleSig)
		if err != nil {
			return nil, err
		}
	}

	//	balanceProof               BalanceProof
	serializedBpf, err := pp.serializeBalanceProof(txWitness.balanceProof)
	if err != nil {
		return nil, err
	}
	// we did not use writeVarBytes(), to avoid define the maxAllowedLength used in readVarBytes().
	// But for safety and robustness, we serialize the length of serializedBpf.
	bpfLen := len(serializedBpf)
	err = WriteVarInt(w, uint64(bpfLen))
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedBpf) //	here we use fixed-length, since in the deserialization, we can call pp.balanceProofTrTxSerializeSize() to get the balance proof size.
	if err != nil {
		return nil, err
	}

	// an assert, could be removed when test is finished
	serializedBpfExpectedLen, err := pp.balanceProofTrTxSerializeSize(txWitness.inForRing, txWitness.outForRing, txWitness.vPublic)
	if len(serializedBpf) != serializedBpfExpectedLen {
		return nil, fmt.Errorf("SerializeTxWitnessTrTx: the length of serializedBpfExpectedLen is not the same as expected")
	}

	return w.Bytes(), err
}

// DeserializeTxWitnessTrTx deserialize the input []byte to TxWitnessTrTx.
// reviewed on 2023.12.19
// todo: reviewed by Alice, 2024.07.05
func (pp *PublicParameter) DeserializeTxWitnessTrTx(serializedTxWitness []byte) (*TxWitnessTrTx, error) {

	if len(serializedTxWitness) == 0 {
		return nil, fmt.Errorf("DeserializeTxWitnessTrTx: the input serializedTxWitness is empty")
	}

	r := bytes.NewReader(serializedTxWitness)

	// txCase       TxWitnessCbTxCase
	txCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	inForRing                  uint8
	inForRing, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	inForSingle                uint8
	inForSingle, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	inForSingleDistinct        uint8
	inForSingleDistinct, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	inRingSizes                []uint8
	inRingSizes := make([]uint8, inForRing)
	for i := uint8(0); i < inForRing; i++ {
		inRingSizes[i], err = r.ReadByte()
		if err != nil {
			return nil, err
		}
	}

	//	outForRing                 uint8
	outForRing, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	outForSingle               uint8
	outForSingle, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	vPublic                    int64
	vPublicRead, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return nil, err
	}
	vPublic := int64(vPublicRead)

	//	ma_ps                      []*PolyANTT
	ma_ps := make([]*PolyANTT, inForRing)
	for i := uint8(0); i < inForRing; i++ {
		ma_ps[i], err = pp.readPolyANTT(r)
		if err != nil {
			return nil, err
		}
	}

	//	cmts_in_p                  []*ValueCommitment
	cmts_in_p := make([]*ValueCommitment, inForRing)
	valueCommitmentSize := pp.ValueCommitmentSerializeSize()
	for i := uint8(0); i < inForRing; i++ {
		serializedCmt := make([]byte, valueCommitmentSize)
		_, err = r.Read(serializedCmt)
		if err != nil {
			return nil, err
		}
		cmts_in_p[i], err = pp.DeserializeValueCommitment(serializedCmt)
		if err != nil {
			return nil, err
		}
	}

	//	elrSigs                    []*ElrSignatureMLP
	elrSigs := make([]*ElrSignatureMLP, inForRing)
	for i := uint8(0); i < inForRing; i++ {
		serializedElrSig := make([]byte, pp.elrSignatureMLPSerializeSize(inRingSizes[i]))
		_, err = r.Read(serializedElrSig)
		elrSigs[i], err = pp.deserializeElrSignatureMLP(serializedElrSig)
		if err != nil {
			return nil, err
		}
	}

	//	addressPublicKeyForSingles []*AddressPublicKeyForSingle
	addressPublicKeyForSingles := make([]*AddressPublicKeyForSingle, inForSingleDistinct)
	apkForSingleSize := pp.addressPublicKeyForSingleSerializeSize()
	for i := uint8(0); i < inForSingleDistinct; i++ {
		serializedApk := make([]byte, apkForSingleSize)
		_, err = r.Read(serializedApk)
		if err != nil {
			return nil, err
		}
		addressPublicKeyForSingles[i], err = pp.deserializeAddressPublicKeyForSingle(serializedApk)
		if err != nil {
			return nil, err
		}
	}

	//	simpleSigs                 []*SimpleSignatureMLP
	simpleSigs := make([]*SimpleSignatureMLP, inForSingleDistinct)
	simpleSigSize := pp.simpleSignatureSerializeSize()
	for i := uint8(0); i < inForSingleDistinct; i++ {
		serializedSimpleSig := make([]byte, simpleSigSize)
		_, err = r.Read(serializedSimpleSig)
		if err != nil {
			return nil, err
		}
		simpleSigs[i], err = pp.deserializeSimpleSignature(serializedSimpleSig)
		if err != nil {
			return nil, err
		}
	}

	//	balanceProof               BalanceProof
	bpfLen, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	serializedBpfLen, err := pp.balanceProofTrTxSerializeSize(inForRing, outForRing, vPublic)
	if err != nil {
		return nil, err
	}
	if uint64(serializedBpfLen) != bpfLen {
		//	This is to check the length. Actually, we can remove this check, and directly use bpfLen.
		return nil, fmt.Errorf("DeserializeTxWitnessTrTx: the deserialized bpfLen (%v) does not match with the length (%v) implied by the deserialized (inForRing, outForRing, vPublic) (%d, %d, %v)",
			bpfLen, serializedBpfLen, inForRing, outForRing, vPublic)
	}

	serializedBpf := make([]byte, serializedBpfLen)
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	balanceProof, err := pp.deserializeBalanceProof(serializedBpf)
	if err != nil {
		return nil, err
	}

	txWitnessTrTx := &TxWitnessTrTx{
		txCase:                     TxWitnessTrTxCase(txCase),
		inForRing:                  inForRing,
		inForSingle:                inForSingle,
		inForSingleDistinct:        inForSingleDistinct,
		inRingSizes:                inRingSizes,
		outForRing:                 outForRing,
		outForSingle:               outForSingle,
		vPublic:                    vPublic,
		ma_ps:                      ma_ps,
		cmts_in_p:                  cmts_in_p,
		elrSigs:                    elrSigs,
		addressPublicKeyForSingles: addressPublicKeyForSingles,
		simpleSigs:                 simpleSigs,
		balanceProof:               balanceProof,
	}

	if !pp.TxWitnessTrTxSanityCheck(txWitnessTrTx) {
		return nil, fmt.Errorf("DeserializeTxWitnessTrTx: the deserialzied TxWitnessTrTx is not well-form")
	}

	return txWitnessTrTx, nil
}

//	TxWitnessTrTx	end

//	Sanity-Check functions	begin

// TxWitnessCbTxSanityCheck checks whether the input txWitnessCbTx *TxWitnessCbTx is well-from:
// (1) txWitnessCbTx is not nil
// (2) txWitnessCbTx.vL is in the allowed scope
// (3) txWitnessCbTx.outForRing is in the allowed scope
// (4) txWitnessCbTx.outForSingle is in the allowed scope
// (5) txWitnessCbTx.balanceProof is well-form
// (6) (txWitnessCbTx.vL, txWitnessCbTx.outForRing, txWitnessCbTx.outForSingle, txWitnessCbTx.balanceProof.BalanceProofCase) match the rules.
// added and reviewed by Alice, 2024.07.01
// todo: review by 2024.07
func (pp *PublicParameter) TxWitnessCbTxSanityCheck(txWitnessCbTx *TxWitnessCbTx) bool {
	if txWitnessCbTx == nil {
		return false
	}

	V := (uint64(1) << pp.paramN) - 1
	if txWitnessCbTx.vL > V {
		return false
	}

	if txWitnessCbTx.outForRing > pp.paramJ {
		return false
	}
	if txWitnessCbTx.outForSingle > pp.paramJSingle {
		return false
	}

	if !pp.BalanceProofSanityCheck(txWitnessCbTx.balanceProof) {
		return false
	}

	//	matches check	begin
	if txWitnessCbTx.outForRing == 0 {
		if txWitnessCbTx.txCase != TxWitnessCbTxCaseC0 {
			return false
		}

		if txWitnessCbTx.outForSingle == 0 {
			//	There should be at least one output.
			return false
		}

		//	all values on the output side are public.
		if txWitnessCbTx.vL != 0 {
			// vL = Vin - (public value on the output side) must be 0
			return false
		}

		if txWitnessCbTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R0 {
			return false
		}

	} else if txWitnessCbTx.outForRing == 1 {
		if txWitnessCbTx.txCase != TxWitnessCbTxCaseC1 {
			return false
		}

		if txWitnessCbTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R1 {
			return false
		}

	} else {
		//	txWitnessCbTx.outForRing >= 2
		if txWitnessCbTx.txCase != TxWitnessCbTxCaseCn {
			return false
		}

		if txWitnessCbTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
			return false
		}

	}

	//	matches check	end

	return true
}

// TxWitnessTrTxSanityCheck checks whether the input txWitnessTrTx *TxWitnessTrTx is well-from:
// (1) txWitnessTrTx is not nil
// (2) txWitnessTrTx.(inForRing, inForSingle, inForSingleDistinct, inRingSizes) are in the allowed scope, and match with each other.
// (3) txWitnessTrTx.(outForRing, outForSingle) are in the allowed scope, and match with each other.
// (4) txWitnessTrTx.ma_ps match with inForRing and is well-form.
// (5) txWitnessTrTx.cmts_in_p match with inForRing and is well-form.
// (6) txWitnessTrTx.elrSigs is well-form, and match with (inForRing, inRingSizes).
// (7) txWitnessTrTx.addressPublicKeyForSingles match with inForSingleDistinct, and is well-form.
// (8) txWitnessTrTx.simpleSigs  match with inForSingleDistinct, and is well-form.
// (9) txWitnessTrTx.balanceProof is well-form
// (10) txWitnessTrTx.(inForRing, outForRing, vPublic) match each other, and matches wih  txCase and txWitnessTrTx.balanceProof.BalanceProofCase().
// added and reviewed by Alice, 2024.07.01
// todo: review by 2024.07
func (pp *PublicParameter) TxWitnessTrTxSanityCheck(txWitnessTrTx *TxWitnessTrTx) bool {

	if txWitnessTrTx == nil {
		return false
	}

	if txWitnessTrTx.inForRing > pp.paramI {
		return false
	}
	if txWitnessTrTx.inForSingle > pp.paramISingle {
		return false
	}
	if txWitnessTrTx.inForRing == 0 && txWitnessTrTx.inForSingle == 0 {
		return false
	}

	if txWitnessTrTx.inForSingleDistinct > pp.paramISingleDistinct {
		return false
	}
	if txWitnessTrTx.inForSingleDistinct > txWitnessTrTx.inForSingle {
		return false
	}
	if txWitnessTrTx.inForSingle > 0 && txWitnessTrTx.inForSingleDistinct == 0 {
		return false
	}

	if len(txWitnessTrTx.inRingSizes) != int(txWitnessTrTx.inForRing) {
		return false
	}
	for i := uint8(0); i < txWitnessTrTx.inForRing; i++ {
		if txWitnessTrTx.inRingSizes[i] == 0 || txWitnessTrTx.inRingSizes[i] > pp.paramRingSizeMax {
			return false
		}
	}

	if txWitnessTrTx.outForRing > pp.paramJ {
		return false
	}
	if txWitnessTrTx.outForSingle > pp.paramJSingle {
		return false
	}
	if txWitnessTrTx.outForRing == 0 && txWitnessTrTx.outForSingle == 0 {
		return false
	}

	V := (uint64(1) << pp.paramN) - 1
	if (txWitnessTrTx.vPublic > V) || (txWitnessTrTx.vPublic < -V) {
		return false
	}

	if len(txWitnessTrTx.ma_ps) != int(txWitnessTrTx.inForRing) {
		return false
	}
	for i := uint8(0); i < txWitnessTrTx.inForRing; i++ {
		if !pp.PolyANTTSanityCheck(txWitnessTrTx.ma_ps[i]) {
			return false
		}
	}

	if len(txWitnessTrTx.cmts_in_p) != int(txWitnessTrTx.inForRing) {
		return false
	}
	for i := uint8(0); i < txWitnessTrTx.inForRing; i++ {
		if !pp.ValueCommitmentSanityCheck(txWitnessTrTx.cmts_in_p[i]) {
			return false
		}
	}

	if len(txWitnessTrTx.elrSigs) != int(txWitnessTrTx.inForRing) {
		return false
	}
	for i := uint8(0); i < txWitnessTrTx.inForRing; i++ {
		if !pp.ElrSignatureMLPSanityCheck(txWitnessTrTx.elrSigs[i]) {
			return false
		}

		if txWitnessTrTx.elrSigs[i].ringSize != txWitnessTrTx.inRingSizes[i] {
			return false
		}
	}

	if len(txWitnessTrTx.addressPublicKeyForSingles) != int(txWitnessTrTx.inForSingleDistinct) {
		return false
	}

	addressPublicKeyStrMap := make(map[string]int) // There should not be repeated AddressPublicKeyForSingle in the distinct key list.
	for i := uint8(0); i < txWitnessTrTx.inForSingleDistinct; i++ {
		if !pp.AddressPublicKeyForSingleSanityCheck(txWitnessTrTx.addressPublicKeyForSingles[i]) {
			return false
		}

		serializedApk, err := pp.serializeAddressPublicKeyForSingle(txWitnessTrTx.addressPublicKeyForSingles[i])
		if err != nil {
			return false
		}
		apkStr := hex.EncodeToString(serializedApk)
		if _, exists := addressPublicKeyStrMap[apkStr]; exists {
			return false
		}
	}

	if len(txWitnessTrTx.simpleSigs) != int(txWitnessTrTx.inForSingleDistinct) {
		return false
	}
	for i := uint8(0); i < txWitnessTrTx.inForSingleDistinct; i++ {
		if !pp.SimpleSignatureSanityCheck(txWitnessTrTx.simpleSigs[i]) {
			return false
		}
	}

	if !pp.BalanceProofSanityCheck(txWitnessTrTx.balanceProof) {
		return false
	}

	//	the matches check	begin
	if txWitnessTrTx.inForRing == 0 {
		if txWitnessTrTx.outForRing == 0 {
			if txWitnessTrTx.vPublic != 0 {
				//	assert
				return false
			}

			//	return pp.balanceProofL0R0SerializeSize(), nil
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI0C0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R0 {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic > 0 {
				//	assert
				return false
			}

			//  -vPublic = cmt_{out,0}
			//	return pp.balanceProofL0R1SerializeSize(), nil
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI0C1 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R1 {
				return false
			}

		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic > 0 {
				// assert
				return false
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(0, outForRing)
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI0Cn {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
				return false
			}

		}
	} else if txWitnessTrTx.inForRing == 1 {
		if txWitnessTrTx.outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if txWitnessTrTx.vPublic < 0 {
				// assert
				return false
			}

			//	vPublic = cmt_{in,0}
			//	return pp.balanceProofL0R1SerializeSize(), nil
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R1 {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				//	return pp.balanceProofL1R1SerializeSize(), nil
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C1Exact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1R1 {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C1CAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C1IAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1CnExact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1CnCAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1CnIAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}
			}
		}

	} else { //	inForRing >= 2
		if txWitnessTrTx.outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if txWitnessTrTx.vPublic < 0 {
				// assert
				return false
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(0, inForRing)
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC1Exact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC1CAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC1IAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImCnExact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImCnCAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImCnIAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}
			}
		}
	}
	//	the matches check	end

	return true
}

//	Sanity-Check functions	end
