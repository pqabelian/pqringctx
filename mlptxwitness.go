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
	outForRing          uint8
	outForSingle        uint8
	vPublic             int64
	//	abf
	ma_ps                      []*PolyANTT                  // length inForRing, each for one RingCT-privacy Input. The key-image of the signing key, and is the pre-image of SerialNumber.
	cmts_in_p                  []*ValueCommitment           // length inForRing, each for one RingCT-privacy Input. It commits the same value as the consumed Txo.
	elrSigs                    []*elrSignatureMLP           // length inForRing, each for one RingCT-privacy Input.
	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	simpleSigs                 []*simpleSignatureMLP        // length inForSingleDistinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
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
//
//	todo:
func (pp *PublicParameter) TxWitnessTrTxSerializeSize() int {
	//length := 1 + // txCase       TxWitnessCbTxCase
	//	8 + // vL           uint64
	//	1 // outForRing   uint8
	//
	////	 balanceProof BalanceProof
	//bpfLen := 0
	//if outForRing == 0 {
	//	//	TxWitnessCbTxCaseC0 ==> BalanceProofL0R0
	//	bpfLen = pp.balanceProofL0R0SerializeSize()
	//} else if outForRing == 1 {
	//	//	TxWitnessCbTxCaseC1 ==> BalanceProofL0R1
	//	bpfLen = pp.balanceProofL0R1SerializeSize()
	//} else { // outForRing >= 2
	//	//	TxWitnessCbTxCaseCn ==> BalanceProofLmRn
	//	bpfLen = pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing)
	//}
	//
	//length = length + bpfLen
	//
	//return length
	return 0
}

// todo:
func (pp *PublicParameter) SerializeTxWitnessTrTx(txWitness *TxWitnessTrTx) (serializedTxWitness []byte, err error) {
	//if txWitness == nil {
	//	return nil, errors.New("SerializeTxWitnessCbTx: the input TxWitnessCbTx is nil")
	//}
	//
	//w := bytes.NewBuffer(make([]byte, 0, pp.TxWitnessCbTxSerializeSize(txWitness.outForRing)))
	//
	//// txCase       TxWitnessCbTxCase
	//err = w.WriteByte(byte(txWitness.txCase))
	//if err != nil {
	//	return nil, err
	//}
	//
	//// vL           uint64
	//err = binarySerializer.PutUint64(w, littleEndian, txWitness.vL)
	//if err != nil {
	//	return nil, err
	//}
	//
	//// outForRing   uint8
	//err = w.WriteByte(txWitness.outForRing)
	//if err != nil {
	//	return nil, err
	//}
	//
	//// balanceProof BalanceProof
	//var serializedBpf []byte
	//switch bpfInst := txWitness.balanceProof.(type) {
	//case *BalanceProofL0R0:
	//	if txWitness.outForRing != 0 {
	//		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofL0R0, but the outForRing is not 0")
	//	}
	//	serializedBpf, err = pp.serializeBalanceProofL0R0(bpfInst)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//case *BalanceProofL0R1:
	//	if txWitness.outForRing != 1 {
	//		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofL0R1, but the outForRing is not 1")
	//	}
	//	serializedBpf, err = pp.serializeBalanceProofL0R1(bpfInst)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//case *BalanceProofLmRn:
	//	if txWitness.outForRing < 2 {
	//		return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is BalanceProofLmRn, but the outForRing is not >= 2")
	//	}
	//	serializedBpf, err = pp.serializeBalanceProofLmRn(bpfInst)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//default:
	//	return nil, fmt.Errorf("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is not in the supported cases")
	//}
	//
	//_, err = w.Write(serializedBpf) //	here the length of serializedBpf is not written, since it can be computed from outForRing.
	//if err != nil {
	//	return nil, err
	//}
	//
	//return w.Bytes(), nil
	return nil, err
}

//	TxWitnessTrTx	end
