package pqringctx

import (
	"bytes"
	"fmt"
)

type BalanceProofCase uint8

const (
	BalanceProofCaseL0R0 BalanceProofCase = 0
	BalanceProofCaseL0R1 BalanceProofCase = 1
	BalanceProofCaseL1R1 BalanceProofCase = 2
	BalanceProofCaseLmRn BalanceProofCase = 3
)

type BalanceProof interface {
	BalanceProofCase() BalanceProofCase
}

// BalanceProofL0R0 is for the case where there are no commitments, so that the balance proof is actually empty.
type BalanceProofL0R0 struct {
	balanceProofCase BalanceProofCase
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
func (bpf *BalanceProofL0R0) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL0R1 is for the case of v = cmt.
type BalanceProofL0R1 struct {
	balanceProofCase BalanceProofCase
	// bpf
	chseed []byte
	// zs, as the response, need to have infinite normal in a scope, say [-(eta_c - beta_c), (eta_c - beta_c)].
	// That is why we use PolyCVec rather than PolyCNTTVec.
	zs []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
func (bpf *BalanceProofL0R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL1R1 is for the case of cmt1 = cmt2
type BalanceProofL1R1 struct {
	balanceProofCase BalanceProofCase
	// bpf
	psi    *PolyCNTT
	chseed []byte
	//	zs1 and zs2, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	zs1 []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	zs2 []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
func (bpf *BalanceProofL1R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofLmRn covers the cases where rpulpproof has to be used, including
// L0Rn:  v = cmt_1 + ... + cmt_n, where n >= 2
// L1R1A: cmtL = cmtR + vRPub, where vRPub > 0
// L1Rn:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2
// LmR1A: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where vRPub > 0
// LmRn:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2
// Note that
// (1) L0Rn has rpulpproof with RpUlpTypeL0Rn,
// (2) L1R1A and L1Rn have rpulpproof with RpUlpTypeL1Rn,
// (3) LmR1A and LmRn have rpulpproof with RpUlpTypeLmRn.
// That is, the RpUlpType of the associated rpulpproof is determined by the number of commitments on left-side.
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

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
func (bpf *BalanceProofLmRn) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}
func (bpf *BalanceProofLmRn) LeftCommNum() uint8 {
	return bpf.leftCommNum
}
func (bpf *BalanceProofLmRn) RightCommNum() uint8 {
	return bpf.rightCommNum
}

// balanceProofL0R0SerializeSize returns the serialize size for balanceProofL0R0.
func (pp *PublicParameter) balanceProofL0R0SerializeSize() int {
	n := 1 // balanceProofCase BalanceProofCase
	return n
}

// serializeBalanceProofL0R0 serialize the input BalanceProofL0R0 to []byte.
func (pp *PublicParameter) serializeBalanceProofL0R0(bpf *BalanceProofL0R0) ([]byte, error) {

	w := bytes.NewBuffer(make([]byte, 0, pp.balanceProofL0R0SerializeSize()))

	//	balanceProofCase BalanceProofCase
	err := w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// deserializeBalanceProofL0R0 deserialize the input []byte to a BalanceProofL0R0.
func (pp *PublicParameter) deserializeBalanceProofL0R0(serializedBpfL0R0 []byte) (*BalanceProofL0R0, error) {

	r := bytes.NewReader(serializedBpfL0R0)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseL0R0 {
		return nil, fmt.Errorf("deserializeBalanceProofL0R0: the deserialized balanceProofCase is not BalanceProofCaseL0R0")
	}

	return &BalanceProofL0R0{
		balanceProofCase: BalanceProofCaseL0R0,
	}, nil
}

// balanceProofL0R1SerializeSize returns the serialized size for balanceProofL0R1.
func (pp *PublicParameter) balanceProofL0R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		HashOutputBytesLen + // chseed           []byte
		+pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofL0R1 serialize the input BalanceProofL0R1 to []byte.
func (pp *PublicParameter) serializeBalanceProofL0R1(bpf *BalanceProofL0R1) ([]byte, error) {

	w := bytes.NewBuffer(make([]byte, 0, pp.balanceProofL0R1SerializeSize()))

	//	balanceProofCase BalanceProofCase
	err := w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	//	chseed           []byte
	_, err = w.Write(bpf.chseed)
	if err != nil {
		return nil, err
	}

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

// deserializeBalanceProofL0R1 deserialize the input []byte to a BalanceProofL0R1.
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
		chseed:           chseed,
		zs:               zs,
	}, nil
}

// balanceProofL1R1SerializeSize returns the serialized size for balanceProofL1R1.
func (pp *PublicParameter) balanceProofL1R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		pp.PolyCNTTSerializeSize() + //  psi              *PolyCNTT
		HashOutputBytesLen + // chseed           []byte
		+2*pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs1, zs2        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofLR1 serialize the input BalanceProofL1R1 to []byte.
func (pp *PublicParameter) serializeBalanceProofLR1(bpf *BalanceProofL1R1) ([]byte, error) {

	w := bytes.NewBuffer(make([]byte, 0, pp.balanceProofL1R1SerializeSize()))

	//	balanceProofCase BalanceProofCase
	err := w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	//	 psi              *PolyCNTT
	err = pp.writePolyCNTT(w, bpf.psi)
	if err != nil {
		return nil, err
	}

	//	chseed           []byte
	_, err = w.Write(bpf.chseed)
	if err != nil {
		return nil, err
	}

	//	zs1               []*PolyCVec
	//	fixed-length paramK
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, bpf.zs1[i])
		if err != nil {
			return nil, err
		}
	}

	//	zs2               []*PolyCVec
	//	fixed-length paramK
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, bpf.zs2[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// deserializeBalanceProofL1R1 deserialize the input []byte to a BalanceProofL1R1.
func (pp *PublicParameter) deserializeBalanceProofL1R1(serializdBpfL1R1 []byte) (*BalanceProofL1R1, error) {

	r := bytes.NewReader(serializdBpfL1R1)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseL1R1 {
		return nil, fmt.Errorf("deserializeBalanceProofL1R1: the deserialized balanceProofCase is not BalanceProofCaseL1R1")
	}

	//	psi              *PolyCNTT
	var psi *PolyCNTT
	psi, err = pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//	chseed           []byte
	chseed := make([]byte, HashOutputBytesLen)
	_, err = r.Read(chseed)
	if err != nil {
		return nil, err
	}

	//	zs1               []*PolyCVec
	//	fixed-length paramK
	zs1 := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs1[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	//	zs2               []*PolyCVec
	//	fixed-length paramK
	zs2 := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs2[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	return &BalanceProofL1R1{
		balanceProofCase: BalanceProofCaseL1R1,
		psi:              psi,
		chseed:           chseed,
		zs1:              zs1,
		zs2:              zs2,
	}, nil
}

// balanceProofLmRnSerializeSizeByCommNum returns the serialize size for BalanceProofLmRn,
// according to the left-side commitment number nL and the right-side commitment number nR.
// The leftCommNum and rightCommNum are also serialized, since the size can be deterministically computed from these two values.
func (pp *PublicParameter) balanceProofLmRnSerializeSizeByCommNum(nL uint8, nR uint8) int {

	length := 1 + // balanceProofCase BalanceProofCase
		1 + // leftCommNum      uint8
		1 + // rightCommNum     uint8
		pp.PolyCNTTVecSerializeSizeByVecLen(pp.paramKC) // b_hat            *PolyCNTTVec, with length pp.paramKC

	n := nL + nR // the number of commitments to call rpulpProveMLP
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

	length = length + int(n2)*pp.PolyCNTTSerializeSize() + // c_hats           []*PolyCNTT, length n2
		pp.CarryVectorRProofSerializeSize() //	u_p              []int64	, dimension paramK, bounded \eta_f

	length = length + pp.rpulpProofMLPSerializeSizeByCommNum(nL, nR) //  rpulpproof       *RpulpProofMLP

	return length
}

// serializeBalanceProofLmRn serialize the input BalanceProofLmRn to []byte.
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
	n := nL + nR // the number of commitments to call rpulpProveMLP
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

// deserializeBalanceProofLmRn deserialize the input []byte to a BalanceProofLmRn.
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
	n := nL + nR // the number of commitments to call rpulpProveMLP
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

	// rpulpproof       *rpulpProofMLP
	serializedRpUlpProofBytes := make([]byte, pp.rpulpProofMLPSerializeSizeByCommNum(leftCommNum, rightCommNum))
	_, err = r.Read(serializedRpUlpProofBytes)
	if err != nil {
		return nil, err
	}
	rpUlpProof, err := pp.deserializeRpulpProofMLP(serializedRpUlpProofBytes)
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
