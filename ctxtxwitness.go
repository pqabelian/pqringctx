package pqringctx

import (
	"bytes"
	"fmt"
	"io"
)

// TxWitnessCbTx defines the TxWitness for coinbase-transaction.
// vL = vin - sum of (public value on output side), it must be >= 0.
// Note that with (outForRing),
// we can deterministically decide txCase and balanceProof's case,
// as well as the rpulp case of the balanceProof (if it has, say BalanceProofLmRnGeneral).
type CtxTxWitnessCbTx struct {
	txCase       TxWitnessCbTxCase
	vL           uint64
	outForRing   uint8
	outForSingle uint8
	//	bpf
	balanceProof BalanceProof
}

// TxCase returns TxWitnessCbTx.txCase.
func (txWitness *CtxTxWitnessCbTx) TxCase() TxWitnessCbTxCase {
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
type CtxTxWitnessTrTx struct {
	txCase       TxWitnessTrTxCase
	inForRing    uint8
	inForSingle  uint8
	outForRing   uint8
	outForSingle uint8
	vPublic      int64
	balanceProof BalanceProof
}

// TxCase returns the txCase of TxWitnessTrTx.
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (txWitness *CtxTxWitnessTrTx) TxCase() TxWitnessTrTxCase {
	return txWitness.txCase
}

// TxWitnessCbTx	begin

// TxWitnessCbTxSerializeSize returns the serialized size for the input TxWitnessCbTx.
func (pp *PublicParameter) CtxTxWitnessCbTxSerializeSize(outForRing uint8) (int, error) {
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
func (pp *PublicParameter) SerializeCtxTxWitnessCbTx(txWitness *CtxTxWitnessCbTx) (serializedTxWitness []byte, err error) {

	if !pp.CtxTxWitnessCbTxSanityCheck(txWitness) {
		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx is not well-form")
	}

	length, err := pp.CtxTxWitnessCbTxSerializeSize(txWitness.outForRing)
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
	// But for safety and robustness, we serialize the length of serializedBpf,
	// and in the corresponding deserialization, a length check is performed.
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
func (pp *PublicParameter) DeserializeCtxTxWitnessCbTx(serializedTxWitness []byte) (txWitness *CtxTxWitnessCbTx, err error) {
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
		// This is to check the length. Actually, we can remove this check, and directly use bpfLen.
		// do not remove this check, since it provides some safe guarantee that the bpfLen is not too large.
		return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized bpfLen (%v) does not match with the length (%v) implied by the deserialized outForRing (%d)",
			bpfLen, serializedBpfLen, outForRing)
	}

	serializedBpf := make([]byte, serializedBpfLen)
	_, err = io.ReadFull(r, serializedBpf)
	if err != nil {
		return nil, err
	}
	balanceProof, err := pp.deserializeBalanceProof(serializedBpf)
	if err != nil {
		return nil, err
	}

	txWitnessCbTx := &CtxTxWitnessCbTx{
		txCase:       TxWitnessCbTxCase(txCase),
		vL:           vL,
		outForRing:   outForRing,
		outForSingle: outForSingle,
		balanceProof: balanceProof,
	}

	if !pp.CtxTxWitnessCbTxSanityCheck(txWitnessCbTx) {
		return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialzed TxWitnessCbTx is not well-form")
	}

	return txWitnessCbTx, nil

}

//	TxWitnessCbTx	end

// TxWitnessTrTx	begin

// TxWitnessTrTxSerializeSize returns the serialize size for TxWitnessTrTx.
func (pp *PublicParameter) CtxTxWitnessTrTxSerializeSize(inForRing uint8, outForRing uint8, vPublic int64) (int, error) {

	length := 1 + //	txCase                     TxWitnessTrTxCase
		2 + //	inForRing uint8, inForSingle uint8
		2 + // outForRing uint8, outForSingle uint8
		8 //	vPublic                    int64

	//	balanceProof               BalanceProof
	serializedBpfLen, err := pp.balanceProofTrTxSerializeSize(inForRing, outForRing, vPublic)
	if err != nil {
		return 0, err
	}
	length = length + VarIntSerializeSize(uint64(serializedBpfLen)) + serializedBpfLen

	return length, err
}

// SerializeTxWitnessTrTx serialize TxWitnessTrTx to []byte.
func (pp *PublicParameter) SerializeCtxTxWitnessTrTx(txWitness *CtxTxWitnessTrTx) (serializedTxWitness []byte, err error) {

	if !pp.CtxTxWitnessTrTxSanityCheck(txWitness) {
		return nil, fmt.Errorf("SerializeTxWitnessTrTx: the input txWitness *TxWitnessTrTx is not well-form")
	}

	length, err := pp.CtxTxWitnessTrTxSerializeSize(txWitness.inForRing, txWitness.outForRing, txWitness.vPublic)
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
func (pp *PublicParameter) DeserializeCtxTxWitnessTrTx(serializedTxWitness []byte) (*CtxTxWitnessTrTx, error) {

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
		// This is to check the length. Actually, we can remove this check, and directly use bpfLen.
		// This check is necessary, as it guarantees that bpfLen is not too large.
		return nil, fmt.Errorf("DeserializeTxWitnessTrTx: the deserialized bpfLen (%v) does not match with the length (%v) implied by the deserialized (inForRing, outForRing, vPublic) (%d, %d, %v)",
			bpfLen, serializedBpfLen, inForRing, outForRing, vPublic)
	}

	serializedBpf := make([]byte, serializedBpfLen)
	_, err = io.ReadFull(r, serializedBpf)
	if err != nil {
		return nil, err
	}
	balanceProof, err := pp.deserializeBalanceProof(serializedBpf)
	if err != nil {
		return nil, err
	}

	txWitnessTrTx := &CtxTxWitnessTrTx{
		txCase:       TxWitnessTrTxCase(txCase),
		inForRing:    inForRing,
		inForSingle:  inForSingle,
		outForRing:   outForRing,
		outForSingle: outForSingle,
		vPublic:      vPublic,
		balanceProof: balanceProof,
	}

	if !pp.CtxTxWitnessTrTxSanityCheck(txWitnessTrTx) {
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
func (pp *PublicParameter) CtxTxWitnessCbTxSanityCheck(txWitnessCbTx *CtxTxWitnessCbTx) bool {
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

	// assume x > 1, y > 1, z > 0
	// case summary by tuple (nRing,nSingle,vL)
	// (0,0,0) (0,0,z)
	// (0,1,0) (0,1,z)
	// (0,y,0) (0,y,z)
	// (1,0,0) (1,0,z)
	// (1,1,0) (1,1,z)
	// (1,y,0) (1,y,z)
	// (x,0,0) (x,0,z)
	// (x,1,0) (x,1,z)
	// (x,y,0) (x,y,z)
	//
	// impossible (0,0,0) (0,0,z) (0,1,z) (0,y,z)
	// banned     (1,0,0) (1,1,0) (1,y,0) (x,0,0) (x,1,0) (x,y,0) (x,0,z) & x>z (x,1,z) & x>z (x,y,z) & x>z
	// special    (0,1,0)
	// allowed    (0,y,0) (1,0,z) (1,1,z) (1,y,z) (x,0,z)  & x<=z (x,1,z) & x<=z (x,y,z) & x<=z
	//	matches check	begin
	if txWitnessCbTx.outForRing == 0 {
		if txWitnessCbTx.txCase != TxWitnessCbTxCaseC0 {
			return false
		}
		// (0,0,0) (0,0,z)
		// [(0,1,0)] (0,1,z)
		// [(0,y,0)] (0,y,z)
		if txWitnessCbTx.outForSingle == 0 { // (0,0,0) (0,0,z)
			//	There should be at least one output.
			return false
		}

		// [(0,1,0)] (0,1,z)
		// (0,y,0) (0,y,z)
		//	all values on the output side are public.
		if txWitnessCbTx.vL != 0 { //  (0,1,z) (0,y,z)
			// vL = Vin - (public value on the output side) must be 0
			return false
		}
		// TODO 20240708 disallow (0,y,0)

		// [(0,1,0)]
		// [(0,y,0)]
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

		// (1,0,0) [(1,0,z)]
		// (1,1,0) [(1,1,z)]
		// (1,y,0) [(1,y,z)]
		if txWitnessCbTx.vL == 0 { // (1,0,0) (1,1,0) (1,y,0)
			// As vL = Vin - (public value on the output side),
			// this implies that the output ValueCommitment has value 0, which can be publicly deduced.
			// It is banned by rules.
			return false
		}

		//         [(1,0,z)]
		//         [(1,1,z)]
		//         [(1,y,z)]

	} else {
		//	txWitnessCbTx.outForRing >= 2
		if txWitnessCbTx.txCase != TxWitnessCbTxCaseCn {
			return false
		}

		if txWitnessCbTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
			return false
		}

		// impossible
		// banned     (x,0,0) (x,1,0) (x,y,0) (x,0,z) & x>z (x,1,z) & x>z (x,y,z) & x>z
		// special
		// allowed    (x,0,z)  & x<=z (x,1,z) & x<=z (x,y,z) & x<=z

		// (x,0,0) (x,0,z) & x>z [(x,0,z) & x<=z]
		// (x,1,0) (x,1,z) & x>z [(x,1,z) & x<=z]
		// (x,y,0) (x,y,z) & x>z [(x,y,z) & x<=z]
		if txWitnessCbTx.vL < uint64(txWitnessCbTx.outForRing) {
			//	It can be deduced that at least one of the output ValueCommitments has value 0.
			//	It is banned by rules.
			return false
		}
		// [(x,0,z) & x<=z]
		// [(x,1,z) & x<=z]
		// [(x,y,z) & x<=z]

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
func (pp *PublicParameter) CtxTxWitnessTrTxSanityCheck(txWitnessTrTx *CtxTxWitnessTrTx) bool {

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
	if (txWitnessTrTx.vPublic > int64(V)) || (txWitnessTrTx.vPublic < -int64(V)) {
		return false
	}

	if !pp.BalanceProofSanityCheck(txWitnessTrTx.balanceProof) {
		return false
	}

	//	the matches check	begin
	// tuple (inForRing,outForRing,vPublic)
	if txWitnessTrTx.inForRing == 0 { // (0,?,?)
		if txWitnessTrTx.outForRing == 0 { // (0,0,?)
			if txWitnessTrTx.vPublic != 0 { // (0,0,>0)
				//	assert
				return false
			}
			// (0,0,0)

			//	return pp.balanceProofL0R0SerializeSize(), nil
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI0C0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R0 {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 { //(0,1,?)
			//	0 = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic > 0 { // (0,1,>0)
				//	assert
				return false
			}

			if txWitnessTrTx.vPublic == 0 { // (0,1,0)
				//	It can be deduced that the value in cmt_{out,0} is 0.
				//  This case is banned by the rules.
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

		} else { //	outForRing >= 2 // (0,>=2,?)
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic > 0 { // (0,>=2,>0)
				// assert
				return false
			} else if txWitnessTrTx.vPublic == 0 { // (0,>=2,0)
				//	It can be deduced that all the values in cmt_{out,0},  ... , cmt_{out, outForRing-1} are 0.
				//  This case is banned by the rules.
				return false
			} else { // (0,>=2,<0)
				//	txWitnessTrTx.vPublic < 0
				if (-txWitnessTrTx.vPublic) < int64(txWitnessTrTx.outForRing) {
					//	It can be deduced that at least one of the values in cmt_{out,0},  ... , cmt_{out, outForRing-1} are 0.
					//  This case is banned by the rules.
					return false
				}
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
	} else if txWitnessTrTx.inForRing == 1 { // (1,?,?)
		if txWitnessTrTx.outForRing == 0 { // (1,0,?)
			//	cmt_{in,0} = vPublic
			if txWitnessTrTx.vPublic < 0 { // (1,0,<0)
				// assert
				return false
			}

			if txWitnessTrTx.vPublic == 0 { // (1,0,0)
				//	do nothing
				//	It can be deduced that the value in cmt_{in,0} is 0, but
				//  the cmt_{in,0} was generated by previous transaction, we should not ban it now.
			}

			// (1,0,>=0)

			//	vPublic = cmt_{in,0}
			//	return pp.balanceProofL0R1SerializeSize(), nil
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0R1 {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 { // (1,1,?)
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic == 0 { // (1,1,0)
				//	cmt_{in,0} = cmt_{out,0}
				//	return pp.balanceProofL1R1SerializeSize(), nil
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C1Exact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1R1 {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 { // (1,1,>0)
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1C1CAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else { // vPublic < 0 // (1,1,<0)
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
		} else { //	outForRing >= 2 // (1,2,?)
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic == 0 { // (1,2,0)
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1CnExact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 { // (1,2,>0)
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseI1CnCAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else { // vPublic < 0 // (1,2,<0)
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

	} else {
		// inForRing >= 2	// (>=2, ?, ?)
		if txWitnessTrTx.outForRing == 0 { // (>=2,0,?)
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if txWitnessTrTx.vPublic < 0 { // (>=2,0,<0)
				// assert
				return false
			}

			if txWitnessTrTx.vPublic == 0 { // (>=2,0,0)
				//	do nothing
				//	It can be deduced that all the values in cmt_{in,0}, ... , cmt_{in, inForRing-1} are 0, but
				//  cmt_{in,0}, ... , cmt_{in, inForRing-1} were generated by previous transactions, we should not ban it now.
				//	return false
			}
			// (>=2,0,>=0)

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(0, inForRing)
			if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC0 {
				return false
			}
			if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
				return false
			}

		} else if txWitnessTrTx.outForRing == 1 { //(>=2,1,?)
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if txWitnessTrTx.vPublic == 0 { //(>=2,1,0)
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(outForRing, inForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC1Exact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 { //(>=2,1,>0)
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImC1CAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else { // vPublic < 0 //(>=2,1,<0)
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

		} else { // outForRing >= 2 // (>=2,>=2,?)
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if txWitnessTrTx.vPublic == 0 { // (>=2,>=2,0)
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImCnExact {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else if txWitnessTrTx.vPublic > 0 { // (>=2,>=2,>0)
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				//	return pp.balanceProofLmRnGeneralSerializeSizeByCommNum(inForRing, outForRing)
				if txWitnessTrTx.txCase != TxWitnessTrTxCaseImCnCAdd {
					return false
				}
				if txWitnessTrTx.balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
					return false
				}

			} else { // vPublic < 0  // (>=2,>=2,<0)
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

//	helper functions 	begin

//	helper functions 	end
