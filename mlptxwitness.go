package pqringctx

import (
	"bytes"
	"errors"
	"fmt"
)

// TxWitnessCbTxCase defines the TxCase which will be used to characterize the TxWitnessCbTx.
// reviewed on 2023.12.07
type TxWitnessCbTxCase uint8

// reviewed on 2023.12.07
const (
	TxWitnessCbTxCaseC0 TxWitnessCbTxCase = 0
	TxWitnessCbTxCaseC1 TxWitnessCbTxCase = 1
	TxWitnessCbTxCaseCn TxWitnessCbTxCase = 2
)

// TxWitnessTrTxCase defines the TxCase which will be used to characterize the TxWitnessTrTx.
// reviewed on 2023.12.18
type TxWitnessTrTxCase uint8

// reviewed on 2023.12.18
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
// as well as the rpulp case of the balanceProof (if it has).
// reviewed on 2023.12.07
type TxWitnessCbTx struct {
	txCase     TxWitnessCbTxCase
	vL         uint64
	outForRing uint8
	//	bpf
	balanceProof BalanceProof
}

// TxCase returns TxWitnessCbTx.txCase.
// reviewed on 2023.12.07
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
// as well as the rpulp case of the balanceProof (if it has).
// reviewed on 2023.12.18
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
	cmts_in_p                  []*ValueCommitment           // length inForRing, each for one RingCT-privacy Input. It commits the same value as the consumed Txo.
	elrSigs                    []*ElrSignatureMLP           // length inForRing, each for one RingCT-privacy Input.
	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	simpleSigs                 []*SimpleSignatureMLP        // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	balanceProof               BalanceProof
}

// TxCase returns the txCase of TxWitnessTrTx.
// reviewed on 2023.12.18
func (txWitness *TxWitnessTrTx) TxCase() TxWitnessTrTxCase {
	return txWitness.txCase
}

// TxWitnessCbTx	begin

// TxWitnessCbTxSerializeSize returns the serialized size for the input TxWitnessCbTx.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
func (pp *PublicParameter) TxWitnessCbTxSerializeSize(outForRing uint8) int {
	length := 1 + // txCase       TxWitnessCbTxCase
		8 + // vL           uint64
		1 // outForRing   uint8

	//	 balanceProof BalanceProof
	bpfLen := 0
	if outForRing == 0 {
		//	TxWitnessCbTxCaseC0 ==> BalanceProofL0R0
		bpfLen = pp.balanceProofL0R0SerializeSize()
	} else if outForRing == 1 {
		//	TxWitnessCbTxCaseC1 ==> BalanceProofL0R1
		bpfLen = pp.balanceProofL0R1SerializeSize()
	} else { // outForRing >= 2
		//	TxWitnessCbTxCaseCn ==> BalanceProofLmRn
		bpfLen = pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing)
	}

	length = length + bpfLen

	return length
}

// SerializeTxWitnessCbTx serialize the input TxWitnessCbTx to []byte.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
func (pp *PublicParameter) SerializeTxWitnessCbTx(txWitness *TxWitnessCbTx) (serializedTxWitness []byte, err error) {
	if txWitness == nil || txWitness.balanceProof == nil {
		return nil, errors.New("SerializeTxWitnessCbTx: there is nil pointer in the input TxWitnessCbTx")
	}

	w := bytes.NewBuffer(make([]byte, 0, pp.TxWitnessCbTxSerializeSize(txWitness.outForRing)))

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

	// balanceProof BalanceProof
	var serializedBpf []byte
	switch bpfInst := txWitness.balanceProof.(type) {
	case *BalanceProofL0R0:
		if txWitness.outForRing != 0 {
			return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofL0R0, but the outForRing is not 0")
		}
		serializedBpf, err = pp.serializeBalanceProofL0R0(bpfInst)
		if err != nil {
			return nil, err
		}

	case *BalanceProofL0R1:
		if txWitness.outForRing != 1 {
			return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofL0R1, but the outForRing is not 1")
		}
		serializedBpf, err = pp.serializeBalanceProofL0R1(bpfInst)
		if err != nil {
			return nil, err
		}

	case *BalanceProofLmRn:
		if txWitness.outForRing < 2 {
			return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofLmRn, but the outForRing is not >= 2")
		}
		serializedBpf, err = pp.serializeBalanceProofLmRn(bpfInst)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is not in the supported cases")
	}

	_, err = w.Write(serializedBpf) //	here the length of serializedBpf is not written, since it can be computed from outForRing.
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// DeserializeTxWitnessCbTx deserialize the input []byte to TxWitnessCbTx.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
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

	// balanceProof BalanceProof
	var balanceProof BalanceProof
	if outForRing == 0 {
		//	BalanceProofL0R0
		if TxWitnessCbTxCase(txCase) != TxWitnessCbTxCaseC0 {
			return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized outForRing is 0 but the txCase is not TxWitnessCbTxCaseC0")
		}

		serializedBpf := make([]byte, pp.balanceProofL0R0SerializeSize())
		_, err = r.Read(serializedBpf)
		if err != nil {
			return nil, err
		}

		balanceProof, err = pp.deserializeBalanceProofL0R0(serializedBpf)
		if err != nil {
			return nil, err
		}

	} else if outForRing == 1 {
		//	BalanceProofL0R1
		if TxWitnessCbTxCase(txCase) != TxWitnessCbTxCaseC1 {
			return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized outForRing is 1 but the txCase is not TxWitnessCbTxCaseC1")
		}

		serializedBpf := make([]byte, pp.balanceProofL0R1SerializeSize())
		_, err = r.Read(serializedBpf)
		if err != nil {
			return nil, err
		}

		balanceProof, err = pp.deserializeBalanceProofL0R1(serializedBpf)
		if err != nil {
			return nil, err
		}
	} else {
		// >= 2, BalanceProofLmRn
		if TxWitnessCbTxCase(txCase) != TxWitnessCbTxCaseCn {
			return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized outForRing is >= 2 but the txCase is not TxWitnessCbTxCaseCn")
		}

		serializedBpf := make([]byte, pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing))
		_, err = r.Read(serializedBpf)
		if err != nil {
			return nil, err
		}

		balanceProof, err = pp.deserializeBalanceProofLmRn(serializedBpf)
		if err != nil {
			return nil, err
		}
	}

	return &TxWitnessCbTx{
		txCase:       TxWitnessCbTxCase(txCase),
		vL:           vL,
		outForRing:   outForRing,
		balanceProof: balanceProof,
	}, nil
}

//	TxWitnessCbTx	end

// TxWitnessTrTx	begin

// balanceProofTrTxSerializeSize returns the serialize for the BalanceProof for TxWitnessTrTx, according to the input (inForRing uint8, outForRing uint8, vPublic int64).
// todo: review
func (pp *PublicParameter) balanceProofTrTxSerializeSize(inForRing uint8, outForRing uint8, vPublic int64) (int, error) {

	if inForRing == 0 {
		if outForRing == 0 {
			if vPublic != 0 {
				//	assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing == 0, but vPublic != 0")
			}

			return pp.balanceProofL0R0SerializeSize(), nil

		} else if outForRing == 1 {
			//	0 = cmt_{out,0} + vPublic
			if vPublic > 0 {
				//	assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing == 1, but vPublic > 0")
			}
			//  -vPublic = cmt_{out,0}
			return pp.balanceProofL0R1SerializeSize(), nil

		} else { //	outForRing >= 2
			//	0 = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic > 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 0 and outForRing >= 2, but vPublic > 0")
			}

			//	(-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
			return pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing), nil

		}
	} else if inForRing == 1 {
		if outForRing == 0 {
			//	cmt_{in,0} = vPublic
			if vPublic < 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing == 1 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0}
			return pp.balanceProofL0R1SerializeSize(), nil

		} else if outForRing == 1 {
			//	cmt_{in,0} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0}
				return pp.balanceProofL1R1SerializeSize(), nil
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing), nil
			}
		} else { //	outForRing >= 2
			//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil
			} else if vPublic > 0 {
				//	cmt_{in,0} = cmt_{out,0} + ...+ cmt_{out, outForRing-1} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil
			} else { // vPublic < 0
				//	cmt_{in,0} + (-vPublic) = cmt_{out,0} + ...+ cmt_{out, outForRing-1}
				//	cmt_{out,0} + ...+ cmt_{out, outForRing-1} = cmt_{in,0} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing), nil
			}
		}

	} else { //	inForRing >= 2
		if outForRing == 0 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = vPublic
			if vPublic < 0 {
				// assert
				return 0, fmt.Errorf("balanceProofTrTxSerializeSize: this should not happen, where inForRing >= 2 and outForRing == 0, but vPublic < 0")
			}

			//	vPublic = cmt_{in,0} + ... + cmt_{in, inForRing-1}
			return pp.balanceProofLmRnSerializeSizeByCommNum(0, inForRing), nil

		} else if outForRing == 1 {
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing), nil
			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil
			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0}
				//	cmt_{out,0} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing), nil
			}

		} else { // outForRing >= 2
			//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
			if vPublic == 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil

			} else if vPublic > 0 {
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} = cmt_{out,0} + ... + cmt_{out, outForRing-1} + vPublic
				return pp.balanceProofLmRnSerializeSizeByCommNum(inForRing, outForRing), nil

			} else { // vPublic < 0
				//	cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic) = cmt_{out,0} + ... + cmt_{out, outForRing-1}
				//	cmt_{out,0} + ... + cmt_{out, outForRing-1} = cmt_{in,0} + ... + cmt_{in, inForRing-1} + (-vPublic)
				return pp.balanceProofLmRnSerializeSizeByCommNum(outForRing, inForRing), nil
			}
		}
	}
}

// TxWitnessTrTxSerializeSize returns the serialize size for TxWitnessTrTx.
// todo:
func (pp *PublicParameter) TxWitnessTrTxSerializeSize(inForRing uint8, inForSingleDistinct uint8,
	outForRing uint8, ringSizes []uint8, vPublic int64) (int, error) {

	length := 1 + //	txCase                     TxWitnessTrTxCase
		3 + //	inForRing uint8, inForSingle uint8, inForSingleDistinct uint8,
		int(inForRing)*1 + // inRingSizes                []uint8
		2 + // outForRing uint8, outForSingle uint8
		8 + //	vPublic                    int64
		int(inForRing)*pp.PolyANTTSerializeSize() + //	ma_ps                      []*PolyANTT
		int(inForRing)*pp.ValueCommitmentSerializeSize() //	cmts_in_p                  []*ValueCommitment

	//	elrSigs                    []*ElrSignatureMLP
	for i := 0; i < int(inForRing); i++ {
		elrSigSize := pp.elrSignatureMLPSerializeSize(int(ringSizes[i]))
		length = length + VarIntSerializeSize(uint64(elrSigSize)) + elrSigSize
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
	length = length + serializedBpfLen

	return length, err
}

// SerializeTxWitnessTrTx serialize TxWitnessTrTx to []byte.
// todo: review
func (pp *PublicParameter) SerializeTxWitnessTrTx(txWitness *TxWitnessTrTx) (serializedTxWitness []byte, err error) {

	if txWitness == nil {
		return nil, err
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

// deserializeTxWitnessTrTx deserialize the input []byte to TxWitnessTrTx.
// todo: review
func (pp *PublicParameter) deserializeTxWitnessTrTx(serializedTxWitness []byte) (*TxWitnessTrTx, error) {

	if len(serializedTxWitness) == 0 {
		return nil, fmt.Errorf("deserializeTxWitnessTrTx: the input serializedTxWitness is empty")
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
	vPublic, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return nil, err
	}

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
	serializedCmt := make([]byte, pp.ValueCommitmentSerializeSize())
	for i := uint8(0); i < inForRing; i++ {
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
	serializedApk := make([]byte, pp.addressPublicKeyForSingleSerializeSize())
	for i := uint8(0); i < inForSingleDistinct; i++ {
		_, err = r.Read(serializedApk)
		addressPublicKeyForSingles[i], err = pp.deserializeAddressPublicKeyForSingle(serializedApk)
		if err != nil {
			return nil, err
		}
	}

	//	simpleSigs                 []*SimpleSignatureMLP
	simpleSigs := make([]*SimpleSignatureMLP, inForSingleDistinct)
	serializedSimpleSig := make([]byte, inForSingleDistinct)
	for i := uint8(0); i < inForSingleDistinct; i++ {
		_, err = r.Read(serializedSimpleSig)
		simpleSigs[i], err = pp.deserializeSimpleSignature(serializedSimpleSig)
		if err != nil {
			return nil, err
		}
	}

	//	balanceProof               BalanceProof
	serializedBpfLen, err := pp.balanceProofTrTxSerializeSize(inForRing, outForRing, int64(vPublic))
	if err != nil {
		return nil, err
	}
	serializedBpf := make([]byte, serializedBpfLen)
	_, err = r.Read(serializedBpf)
	balanceProof, err := pp.deserializeBalanceProof(serializedBpf)
	if err != nil {
		return nil, err
	}

	return &TxWitnessTrTx{
		txCase:                     TxWitnessTrTxCase(txCase),
		inForRing:                  inForRing,
		inForSingle:                inForSingle,
		inForSingleDistinct:        inForSingleDistinct,
		inRingSizes:                inRingSizes,
		outForRing:                 outForRing,
		outForSingle:               outForSingle,
		vPublic:                    int64(vPublic),
		ma_ps:                      ma_ps,
		cmts_in_p:                  cmts_in_p,
		elrSigs:                    elrSigs,
		addressPublicKeyForSingles: addressPublicKeyForSingles,
		simpleSigs:                 simpleSigs,
		balanceProof:               balanceProof,
	}, nil
}

//	TxWitnessTrTx	end
