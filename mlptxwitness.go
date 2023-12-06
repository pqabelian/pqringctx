package pqringctx

import (
	"bytes"
	"errors"
	"fmt"
)

type TxWitnessCbTxCase uint8

const (
	TxWitnessCbTxCaseC0 TxWitnessCbTxCase = 0
	TxWitnessCbTxCaseC1 TxWitnessCbTxCase = 1
	TxWitnessCbTxCaseCn TxWitnessCbTxCase = 2
)

type TxCaseTrTx uint8

const (
	TxCaseTrTxI0C0 TxCaseTrTx = 0
	TxCaseTrTxI0C1 TxCaseTrTx = 1
	TxCaseTrTxI1C1 TxCaseTrTx = 1
)

// TxWitnessMLP is used as a component object for CoinbaseTxMLP and TransferTxMLP.
// As the TxWitnessMLP for different CoinbaseTxMLP/TransferTxMLP instances could have different structures,
// here we use []byte to denote Txo (in its serialized form).
// type TxWitnessMLP []byte
// Note: We do not define standalone structure for TxWitness.
//
//	This is because:
//	TxWitness is purely at the cryptography layer, and the caller of PQRINGCTX does not need to learn the details of TxWitness.
//	PQRINGCTX will be responsible for generating TxWitness and providing service/API on the generated TxWitness.
//type TxWitnessMLP interface {
//	TxCase() TxCase
//}

// TxWitnessCbTx defines the TxWitness for coinbase-transaction.
// vL = vin - sum of (public value on output side), it must be >= 0.
// Note that with (vL, outForRing),
// we can deterministically decide txCase and balanceProof's case,
// as well as the rpulp case of the balanceProof (if it has).
type TxWitnessCbTx struct {
	txCase     TxWitnessCbTxCase
	vL         uint64
	outForRing uint8
	//	bpf
	balanceProof BalanceProof
}

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
type TxWitnessTrTx struct {
	txCase              TxCaseTrTx
	inForRing           uint8
	inForSingle         uint8
	inForSingleDistinct uint8
	outForRing          uint8
	outForSingle        uint8
	vPub                int64
	//	abf
	ma_ps                      []*PolyANTT                  // length I_ring, each for one RingCT-privacy Input. The key-image of the signing key, and is the pre-image of SerialNumber.
	cmt_ps                     []*ValueCommitment           // length I_ring, each for one RingCT-privacy Input. It commits the same value as the consumed Txo.
	elrsSigs                   []*elrsSignatureMLP          // length I_ring, each for one RingCT-privacy Input.
	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	simpsSigs                  []*simpsSignatureMLP         // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
	balanceProof               BalanceProof
}

func (txWitness *TxWitnessTrTx) TxCase() TxCaseTrTx {
	return txWitness.txCase
}

//type TxWitnessTrTx struct {
//	txCase                     TxCase
//	ma_ps                      []*PolyANTT                  // length I_ring, each for one RingCT-privacy Input. The key-image of the signing key, and is the pre-image of SerialNumber.
//	cmt_ps                     []*ValueCommitment           // length I_ring, each for one RingCT-privacy Input. It commits the same value as the consumed Txo.
//	elrsSigs                   []*elrsSignatureMLP          // length I_ring, each for one RingCT-privacy Input.
//	addressPublicKeyForSingles []*AddressPublicKeyForSingle // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
//	simpsSigs                  []*simpsSignatureMLP         // length I_single_distinct, each for one distinct CoinAddress in pseudonym-privacy Inputs.
//	b_hat                      *PolyCNTTVec
//	c_hats                     []*PolyCNTT //	length n_2: n_2 = I+J+2 for I=1, and n_2 = I+J+4 for I >= 2.
//	u_p                        []int64     // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f = D_c (J+1) for I=1 and beta_f = D_c (I+J+1) for I >= 2.
//	rpulpproof                 *rpulpProofMLP
//}

//func (txWitness *TxWitnessTrTx) TxCase() TxCase {
//	return txWitness.txCase
//}

// TxWitnessCbTx	begin
// genTxWitnessCbTx generates TxWitnessCbTx.
func (pp *PublicParameter) genTxWitnessCbTx(serializedCbTxCon []byte, vL uint64, outForRing uint8, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*TxWitnessCbTx, error) {

	//	The caller should guarantee the sanity of the inputs.
	//if len(cmtRs) != int(outForRing) || len(cmtrRs) != int(outForRing) || len(vRs) != int(outForRing) {
	//	return nil, fmt.Errorf("at least one of cmtRs, cmtrRs, vRs has length that does match the input outForRing")
	//}

	if outForRing == 0 && vL != 0 {
		return nil, fmt.Errorf("outForRing == 0 should be accompanied by vL == 0")
	}

	var err error
	txCase := TxWitnessCbTxCaseC0
	var balanceProof BalanceProof
	if outForRing == 0 {
		txCase = TxWitnessCbTxCaseC0
		balanceProof = pp.genBalanceProofL0R0()
	} else if outForRing == 1 {
		txCase = TxWitnessCbTxCaseC1
		balanceProof, err = pp.genBalanceProofL0R1(serializedCbTxCon, vL, cmtRs[0], cmtrRs[0])
		if err != nil {
			return nil, err
		}
	} else {
		//	outForRing >= 2
		txCase = TxWitnessCbTxCaseCn
		balanceProof, err = pp.genBalanceProofL0Rn(serializedCbTxCon, vL, cmtRs, cmtrRs, vRs)
		if err != nil {
			return nil, err
		}
	}

	return &TxWitnessCbTx{
		txCase:       txCase,
		vL:           vL,
		outForRing:   outForRing,
		balanceProof: balanceProof,
	}, nil
}

// TxWitnessCbTxSerializeSize returns the serialized size for the input TxWitnessCbTx.
// todo: to review
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
	} else {
		//	TxWitnessCbTxCaseCn ==> BalanceProofLmRn
		bpfLen = pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing)
	}

	length = length + bpfLen

	return length
}

// SerializeTxWitnessCbTx serialize the input TxWitnessCbTx to []byte
func (pp *PublicParameter) SerializeTxWitnessCbTx(txWitness *TxWitnessCbTx) (serializedTxWitness []byte, err error) {
	if txWitness == nil {
		return nil, errors.New("SerializeTxWitnessCbTx: the input TxWitnessCbTx is nil")
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
		return nil, errors.New("SerializeTxWitnessCbTx: the input TxWitnessCbTx's balanceProof is not in the supported cases")
	}

	_, err = w.Write(serializedBpf)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), err
}

// DeserializeTxWitnessCbTx deserialize the input []byte to TxWitnessCbTx.
// todo: to review
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
	serializedBpf := make([]byte, pp.balanceProofLmRnSerializeSizeByCommNum(0, outForRing))
	_, err = r.Read(serializedBpf)
	if err != nil {
		return nil, err
	}
	if outForRing == 0 {
		//	BalanceProofL0R0
		if TxWitnessCbTxCase(txCase) != TxWitnessCbTxCaseC0 {
			return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized outForRing is 0 but the txCase is not TxWitnessCbTxCaseC0")
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
		balanceProof, err = pp.deserializeBalanceProofL0R1(serializedBpf)
		if err != nil {
			return nil, err
		}
	} else {
		// >= 2, BalanceProofLmRn
		if TxWitnessCbTxCase(txCase) != TxWitnessCbTxCaseCn {
			return nil, fmt.Errorf("DeserializeTxWitnessCbTx: the deserialized outForRing is >= 2 but the txCase is not TxWitnessCbTxCaseCn")
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
