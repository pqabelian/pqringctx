package pqringctx

import (
	"bytes"
	"fmt"
)

type BalanceProofCase uint8

const (
	BalanceProofCaseL0R1 BalanceProofCase = 0
	BalanceProofCaseL0Rn BalanceProofCase = 1
	BalanceProofCaseL1R1 BalanceProofCase = 2
	BalanceProofCaseL1Rn BalanceProofCase = 3
	BalanceProofCaseLmRn BalanceProofCase = 4
)

type BalanceProof interface {
	BalanceProofCase() BalanceProofCase
	LeftCommNum() uint8
	RightCommNum() uint8
}

// balanceProofL0R1 is for the case of v = cmt
type BalanceProofL0R1 struct {
	balanceProofCase BalanceProofCase
	leftCommNum      uint8
	rightCommNum     uint8
	// bpf
	chseed []byte
	// zs, as the response, need to have infinite normal in a scopr, say [-(eta_c - beta_c), (eta_c - beta_c)].
	// That is why we use PolyCVec rather than PolyCNTTVec.
	zs []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
}

func (bpf *BalanceProofL0R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *BalanceProofL0R1) LeftCommNum() uint8 {
	return bpf.leftCommNum
}
func (bpf *BalanceProofL0R1) RightCommNum() uint8 {
	return bpf.rightCommNum
}

// todo
type BalanceProofL1R1 struct {
	balanceProofCase BalanceProofCase
	leftCommNum      uint8
	rightCommNum     uint8
	// bpf
	psi    *PolyCNTT
	chseed []byte
	//	zs1 and zs2, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	zs1 []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
	zs2 []*PolyCVec //	length paramK, each in (S_{eta_c - beta_c})^{L_c}
}

func (bpf *BalanceProofL1R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *BalanceProofL1R1) LeftCommNum() uint8 {
	return bpf.leftCommNum
}
func (bpf *BalanceProofL1R1) RightCommNum() uint8 {
	return bpf.rightCommNum
}

type BalanceProofLmRn struct {
	balanceProofCase BalanceProofCase
	leftCommNum      uint8
	rightCommNum     uint8
	// bpf
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT // length J+2
	u_p        []int64     // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f = D_c J.
	rpulpproof *RpulpProofMLP
}

func (bpf *BalanceProofLmRn) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *BalanceProofLmRn) LeftCommNum() uint8 {
	return bpf.leftCommNum
}
func (bpf *BalanceProofLmRn) RightCommNum() uint8 {
	return bpf.rightCommNum
}

// balanceProofL0R1SerializedSize returned the serialized size for balanceProofL0R1.
// finished and reviewed on 2023.12.04
// todo(MLP): whether need to serialize leftCommNum and rightCommNum
func (pp *PublicParameter) balanceProofL0R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		1 + // leftCommNum      uint8
		1 + // rightCommNum     uint8
		HashOutputBytesLen + // chseed           []byte
		+pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs        []*PolyCVec : length pp.paramK, each Vec has length pp.paramLC
	return n
}

func (pp *PublicParameter) serializeBalanceProofL0R1(bpf *BalanceProofL0R1) ([]byte, error) {

	w := bytes.NewBuffer(make([]byte, 0, pp.balanceProofL0R1SerializeSize()))

	//	balanceProofCase BalanceProofCase
	err := w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	//	leftCommNum      uint8
	err = w.WriteByte(bpf.leftCommNum)
	if err != nil {
		return nil, err
	}

	//	rightCommNum      uint8
	err = w.WriteByte(bpf.rightCommNum)
	if err != nil {
		return nil, err
	}

	//	chseed           []byte
	_, err = w.Write(bpf.chseed)
	if err != nil {
		return nil, err
	}
	//if n != HashOutputBytesLen {
	//	if err != nil {
	//		return nil, fmt.Errorf("serializeBalanceProofL0R1: balanceProofL0R1.chseed should be a hash, namely []byte with length=%d", HashOutputBytesLen)
	//	}
	//}

	//	zs               []*PolyCVec
	//	fixed-length paramK
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, bpf.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

func (pp *PublicParameter) deserializeBalanceProofL0R1(serializdBpfL0R1 []byte) (*BalanceProofL0R1, error) {

	r := bytes.NewReader(serializdBpfL0R1)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseL0R1 {
		return nil, fmt.Errorf("deserializeBalanceProofL0R1: the deserialized balanceProofCase is not BalanceProofCaseL0R1")
	}

	//	leftCommNum      uint8
	leftCommNum, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	rightCommNum      uint8
	rightCommNum, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	chseed           []byte
	chseed := make([]byte, HashOutputBytesLen)
	_, err = r.Read(chseed)
	if err != nil {
		return nil, err
	}

	//	zs               []*PolyCVec
	//	fixed-length paramK
	zs := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	return &BalanceProofL0R1{
		balanceProofCase: BalanceProofCaseL0R1,
		leftCommNum:      leftCommNum,
		rightCommNum:     rightCommNum,
		chseed:           chseed,
		zs:               zs,
	}, nil
}

// balanceProofLmRnSerializedSizeByCommNum returns the serilaize size for balanceProofLmRn,
// according to the left-side commitment number nL and the right-side commitment number nR.
// finished and reviewed on 2023.12.04.
// todo(MLP): whether need to serialize leftCommNum and rightCommNum
func (pp *PublicParameter) balanceProofLmRnSerializeSizeByCommNum(nL uint8, nR uint8) int {
	length := 1 + // balanceProofCase BalanceProofCase
		1 + // leftCommNum      uint8
		1 + // rightCommNum     uint8
		pp.PolyCNTTVecSerializeSizeByVecLen(pp.paramKC) // b_hat            *PolyCNTTVec, with length pp.paramKC

	n := nL + nR // the number of commitments to call rpulpProofMLPProve
	n2 := n      //	the number of commitments for c_hats
	if nL == 0 {
		//	A_{L0R2}
		n2 = n + 2 // f_R, e
	} else if nL == 1 {
		// A_{L1R2}
		n2 = n + 2 // f_R, e
	} else if nL >= 2 {
		// A_{L2R2}
		n2 = n + 4 // m_{sum}, f_L, f_R, e
	}

	length = length + VarIntSerializeSize(uint64(n2))     // n
	length = length + int(n2)*pp.PolyCNTTSerializeSize()  // c_hats           []*PolyCNTT
	length = length + pp.CarryVectorRProofSerializeSize() //	u_p              []int64	, bounded \beta_f
	length = length + pp.rpulpProofMLPSerializeSizeByCommNum(nL, nR)

	return length
}

func (pp *PublicParameter) serializeBalanceProofLmRn(bpf *BalanceProofLmRn) ([]byte, error) {

	w := bytes.NewBuffer(make([]byte, 0, pp.balanceProofLmRnSerializeSizeByCommNum(bpf.leftCommNum, bpf.rightCommNum)))

	//	balanceProofCase BalanceProofCase
	err := w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	//	leftCommNum      uint8
	err = w.WriteByte(bpf.leftCommNum)
	if err != nil {
		return nil, err
	}

	//	rightCommNum      uint8
	err = w.WriteByte(bpf.rightCommNum)
	if err != nil {
		return nil, err
	}

	// b_hat            *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, bpf.b_hat)
	if err != nil {
		return nil, err
	}

	// c_hats           []*PolyCNTT
	nL := bpf.leftCommNum
	nR := bpf.rightCommNum
	n := nL + nR // the number of commitments to call rpulpProofMLPProve
	n2 := n      //	the number of commitments for c_hats
	if nL == 0 {
		//	A_{L0R2}
		n2 = n + 2 // f_R, e
	} else if nL == 1 {
		// A_{L1R2}
		n2 = n + 2 // f_R, e
	} else {
		// nL >= 2
		// A_{L2R2}
		n2 = n + 4 // m_{sum}, f_L, f_R, e
	}
	for i := 0; i < int(n2); i++ {
		err = pp.writePolyCNTT(w, bpf.c_hats[i])
		if err != nil {
			return nil, err
		}
	}

	// u_p              []int64
	err = pp.writeCarryVectorRProof(w, bpf.u_p)
	if err != nil {
		return nil, err
	}

	// rpulpproof       *rpulpProofMLP
	serializedBpf, err := pp.serializeRpulpProofMLP(bpf.rpulpproof)
	_, err = w.Write(serializedBpf)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (pp *PublicParameter) deserializeBalanceProofLmRn(serializedBpfLmRn []byte) (*BalanceProofLmRn, error) {
	r := bytes.NewReader(serializedBpfLmRn)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseLmRn {
		return nil, fmt.Errorf("deserializeBalanceProofLmRn: the deserialized balanceProofCase is not BalanceProofCaseLmRn")
	}

	//	leftCommNum      uint8
	leftCommNum, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	rightCommNum      uint8
	rightCommNum, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// b_hat            *PolyCNTTVec
	b_hat, err := pp.readPolyCNTTVec(r)
	if err != nil {
		return nil, err
	}

	// c_hats           []*PolyCNTT
	nL := leftCommNum
	nR := rightCommNum
	n := nL + nR // the number of commitments to call rpulpProofMLPProve
	n2 := n      //	the number of commitments for c_hats
	if nL == 0 {
		//	A_{L0R2}
		n2 = n + 2 // f_R, e
	} else if nL == 1 {
		// A_{L1R2}
		n2 = n + 2 // f_R, e
	} else {
		//	nL >= 2
		// A_{L2R2}
		n2 = n + 4 // m_{sum}, f_L, f_R, e
	}
	c_hats := make([]*PolyCNTT, n2)
	for i := 0; i < int(n2); i++ {
		c_hats[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}

	// u_p              []int64
	u_p, err := pp.readCarryVectorRProof(r)
	if err != nil {
		return nil, err
	}

	//	zs               []*PolyCVec
	//	fixed-length paramK
	zs := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	// rpulpproof       *rpulpProofMLP
	serializedRpUlpProof := make([]byte, pp.rpulpProofMLPSerializeSizeByCommNum(leftCommNum, rightCommNum))
	rpUlpProof, err := pp.deserializeRpulpProofMLP(serializedRpUlpProof)
	if err != nil {
		return nil, err
	}

	return &BalanceProofLmRn{
		balanceProofCase: BalanceProofCaseLmRn,
		leftCommNum:      leftCommNum,
		rightCommNum:     rightCommNum,
		b_hat:            b_hat,
		c_hats:           c_hats,
		u_p:              u_p,
		rpulpproof:       rpUlpProof,
	}, nil
}
