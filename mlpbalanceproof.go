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

// BalanceProof defines an interface for multiple types of balance-proof.
// reviewed on 2023.12.07
type BalanceProof interface {
	BalanceProofCase() BalanceProofCase
}

// BalanceProofL0R0 is for the case where there are no commitments, so that the balance proof is actually empty.
// reviewed on 2023.12.07
type BalanceProofL0R0 struct {
	balanceProofCase BalanceProofCase
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
// reviewed on 2023.12.07
func (bpf *BalanceProofL0R0) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL0R1 is for the case of v = cmt.
// reviewed on 2023.12.07
type BalanceProofL0R1 struct {
	balanceProofCase BalanceProofCase
	// bpf
	chseed []byte
	// zs, as the response, need to have infinite normal in a scope, say [-(eta_c - beta_c), (eta_c - beta_c)].
	// That is why we use PolyCVec rather than PolyCNTTVec.
	zs []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
// reviewed on 2023.12.07
func (bpf *BalanceProofL0R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL1R1 is for the case of cmt1 = cmt2
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
func (bpf *BalanceProofL1R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofLmRn covers the cases where rpulpProof has to be used, including
// L0Rn:  v = cmt_1 + ... + cmt_n, where n >= 2
// L1R1A: cmtL = cmtR + vRPub, where vRPub > 0
// L1Rn:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2
// LmR1A: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where vRPub > 0
// LmRn:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2
// Note that
// (1) L0Rn has rpulpProof with RpUlpTypeL0Rn,
// (2) L1R1A and L1Rn have rpulpProof with RpUlpTypeL1Rn,
// (3) LmR1A and LmRn have rpulpProof with RpUlpTypeLmRn.
// That is, the RpUlpType of the associated rpulpProof is determined by the number of commitments on left-side.
// Note that
// L0R0 is different from L0Rn in the sense that n=0, which will make the proof has complete different formats.
// L0R1 is different from L0Rn in the sense that n=1, which will make the proof has complete different formats.
// L1R1 is different from L1R1A in the sense that vRPub = 0, which will make the proof has complete different formats.
// The caller will determine which one of (L0R0, L0R1, L1R1, LmRn) is used, based on the numbers of commitments and the public value.
// For self-contained, (leftCommNum, rightCommNum) are contained in the structure.
// reviewed on 2023.12.07
type BalanceProofLmRn struct {
	balanceProofCase BalanceProofCase
	leftCommNum      uint8
	rightCommNum     uint8
	// bpf
	b_hat      *PolyCNTTVec
	c_hats     []*PolyCNTT // length n_2, which is determined by (leftCommNum, rightCommNum).
	u_p        []int64     // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f = D_c J.
	rpulpproof *RpulpProofMLP
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
// reviewed on 2023.12.07
func (bpf *BalanceProofLmRn) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

//func (bpf *BalanceProofLmRn) LeftCommNum() uint8 {
//	return bpf.leftCommNum
//}
//func (bpf *BalanceProofLmRn) RightCommNum() uint8 {
//	return bpf.rightCommNum
//}

// genBalanceProofL0R0 generates a BalanceProofL0R0.
// reviewed on 2023.12.07
func (pp *PublicParameter) genBalanceProofL0R0() (*BalanceProofL0R0, error) {
	return &BalanceProofL0R0{
		balanceProofCase: BalanceProofCaseL0R0,
	}, nil
}

// todo: review
func (pp *PublicParameter) verifyBalanceProofL0R0(balanceProof *BalanceProofL0R0) (bool, error) {
	if balanceProof == nil {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL0R0 {
		return false, nil
	}

	return true, nil
}

// genBalanceProofL0R1 generates BalanceProofL0R1, proving vL = cmt.
// This is almost identical to J == 1 case of pqringct.coinbaseTxGen.
// reviewed on 2023.12.07
func (pp *PublicParameter) genBalanceProofL0R1(preMsg []byte, vL uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) (*BalanceProofL0R1, error) {
	// random from S_etaC^lc
	ys := make([]*PolyCNTTVec, pp.paramK)
	// w^t = B * y^t
	ws := make([]*PolyCNTTVec, pp.paramK)
	// delta = <h,y^t>
	deltas := make([]*PolyCNTT, pp.paramK)
	// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	zs := make([]*PolyCVec, pp.paramK)

balanceProofL0R1Restart:
	for t := 0; t < pp.paramK; t++ {
		// random y
		tmpY, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(tmpY)

		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
		deltas[t] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], ys[t], pp.paramLC)
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0R1(preMsg, vL, cmt, ws, deltas)
	if err != nil {
		return nil, err
	}

	chseed, err := Hash(seedMsg)
	if err != nil {
		return nil, err
	}

	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	chtmp, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(chtmp)
	for t := 0; t < pp.paramK; t++ {
		zs_ntt[t] = pp.PolyCNTTVecAdd(
			ys[t],
			pp.PolyCNTTVecScaleMul(
				pp.sigmaPowerPolyCNTT(ch, t),
				cmtr,
				pp.paramLC,
			),
			pp.paramLC,
		)
		// check the norm
		zs[t] = pp.NTTInvPolyCVec(zs_ntt[t])
		if zs[t].infNorm() > boundC {
			goto balanceProofL0R1Restart
		}
	}

	return &BalanceProofL0R1{
		balanceProofCase: BalanceProofCaseL0R1,
		chseed:           chseed,
		zs:               zs,
	}, nil
}

// verifyBalanceProofL0R1 verifies BalanceProofL0R1.
// todo: review
func (pp *PublicParameter) verifyBalanceProofL0R1(preMsg []byte, vL uint64, cmt *ValueCommitment, balanceProof *BalanceProofL0R1) (bool, error) {
	if len(preMsg) == 0 {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1
	if vL > V {
		return false, nil
	}

	if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
		return false, nil
	}

	if balanceProof == nil || len(balanceProof.chseed) != HashOutputBytesLen || len(balanceProof.zs) != pp.paramK {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL0R1 {
		return false, fmt.Errorf("verifyBalanceProofL0R1: balanceProof.balanceProofCase is not BalanceProofCaseL0R1")
	}

	// infNorm of z^t
	bound := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
		if balanceProof.zs[t] == nil || len(balanceProof.zs[t].polyCs) != pp.paramLC {
			return false, nil
		}
		if balanceProof.zs[t].infNorm() > bound {
			return false, nil
		}
	}

	ws := make([]*PolyCNTTVec, pp.paramK)
	deltas := make([]*PolyCNTT, pp.paramK)

	ch_poly, err := pp.expandChallengeC(balanceProof.chseed)
	if err != nil {
		return false, err
	}
	ch := pp.NTTPolyC(ch_poly)
	mtmp := pp.intToBinary(vL)
	//msg := pp.NTTInRQc(&Polyv2{coeffs1: mtmp})
	msgNTT := &PolyCNTT{coeffs: mtmp}
	for t := 0; t < pp.paramK; t++ {
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)

		zs_ntt := pp.NTTPolyCVec(balanceProof.zs[t])

		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, zs_ntt, pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt.b, pp.paramKC),
			pp.paramKC,
		)
		deltas[t] = pp.PolyCNTTSub(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], zs_ntt, pp.paramLC),
			pp.PolyCNTTMul(
				sigma_t_ch,
				pp.PolyCNTTSub(cmt.c, msgNTT),
			),
		)
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0R1(preMsg, vL, cmt, ws, deltas)
	if err != nil {
		return false, err
	}
	seed_ch, err := Hash(seedMsg)
	if err != nil {
		return false, err
	}

	if bytes.Compare(seed_ch, balanceProof.chseed) != 0 {
		return false, nil
	}

	return true, nil

}

// genBalanceProofL0Rn generates genBalanceProofL0Rn, proving vL = cmts[0] + ... + cmts[nR-1].
// This is almost identical to J >= 2 case of pqringct.coinbaseTxGen.
// Note that this proving algorithm does not check the sanity of the inputs, since we need the corresponding verifying algorithm to guarantee the security.
// reviewed on 2023.12.07
func (pp *PublicParameter) genBalanceProofL0Rn(preMsg []byte, vL uint64, outForRing uint8, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRn, error) {

	nR := outForRing

	n := int(nR)
	n2 := n + 2

	if n != len(cmtRs) || n != len(cmtrRs) || n != len(vRs) {
		return nil, fmt.Errorf("genBalanceProofL0Rn: The input cmtRs, cmtrRs, vRs should have the same length")
	}

	if n > pp.paramJ {
		// Note that pp.paramI == pp.paramI
		return nil, fmt.Errorf("genBalanceProofL0Rn: the number of cmtRs (%d) is not in [2, %d]", n, pp.paramJ)
	}

	c_hats := make([]*PolyCNTT, n2)

	msg_hats := make([][]int64, n2)

	u_hats := make([][]int64, 3)

	u := pp.intToBinary(vL)

	// msg_hats[0], ..., msg_hats[n-1]
	for j := 0; j < n; j++ {
		msg_hats[j] = pp.intToBinary(vRs[j])
	}

	// msg_hats[n] := f
	// f is the carry vector for m_0 + m_1 + ... + m_{n-1}, in particular,
	// f[0] = (m_0[0] + ... + m_{n-1}[0]       )/2
	// f[1] = (m_0[1] + ... + m_{n-1}[1] + f[0])/2
	// ...
	// f[t] = (m_0[t] + ... + m_{n-1}[t] + f[t-1])/2
	// ...
	// f[d-1] = (m_0[d-1] + ... + m_{n-1}[d-1] + f[d-2])/2

	// that is,
	// f[0] = (m_0[0] + ... + m_{n-1}[0]         )/2
	// for t = 1, ..., d-1
	// f[t] = (m_0[t] + ... + m_{n-1}[t] + f[t-1])/2
	f := make([]int64, pp.paramDC)

	// f[0]
	tmp := int64(0)
	for j := 0; j < n; j++ {
		tmp = tmp + msg_hats[j][0]
	}
	f[0] = tmp >> 1

	// f[1], ..., f[d-2], f[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := 0; j < n; j++ {
			tmp = tmp + msg_hats[j][t]
		}
		f[t] = (tmp + f[t-1]) >> 1
	}

	msg_hats[n] = f

	////	f is the carry vector, such that, u = m_0 + m_1 + ... + m_{n-1}
	////	f[0] = 0, and for i=1 to d-1,
	////	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1] + 2 f[i],
	////	m_0[i-1]+ ... + m_{J-1}[i-1] + f[i-1] = u[i-1]
	//f := make([]int64, pp.paramDC)
	//f[0] = 0
	//for i := 1; i < pp.paramDC; i++ {
	//	tmp := int64(0)
	//	for j := 0; j < J; j++ {
	//		tmp = tmp + msg_hats[j][i-1]
	//	}
	//
	//	//	-1 >> 1 = -1, -1/2=0
	//	//	In our design, the carry should be in [0, J] and (tmp + f[i-1] - u[i-1]) >=0,
	//	//	which means >> 1 and /2 are equivalent.
	//	//	A negative carry bit will not pass the verification,
	//	//	and the case (tmp + f[i-1] - u[i-1]) < 0 will not pass the verification.
	//	//	f[0] = 0 and other proved verification (msg[i] \in {0,1}, |f[i]| < q_c/8) are important.
	//	f[i] = (tmp + f[i-1] - u[i-1]) >> 1
	//	// f[i] = (tmp + f[i-1] - u[i-1]) / 2
	//}
	//msg_hats[J] = f

	r_hat_poly, err := pp.sampleValueCmtRandomness()
	if err != nil {
		return nil, err
	}
	r_hat := pp.NTTPolyCVec(r_hat_poly)

	// b_hat =B * r_hat
	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)

	//	c_hats[0]~c_hats[n-1], c_hats[n] (for f)
	for i := 0; i < n+1; i++ {
		msgNTTi, err := pp.NewPolyCNTTFromCoeffs(msg_hats[i])
		if err != nil {
			return nil, err
		}
		c_hats[i] = pp.PolyCNTTAdd(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], r_hat, pp.paramLC),
			msgNTTi,
			//&PolyCNTT{coeffs: msg_hats[i]},
		)
	}

balanceProofL0RnRestart:
	//e := make([]int64, pp.paramDC)
	e, err := pp.randomDcIntegersInQcEtaF()
	if err != nil {
		return nil, err
	}
	msg_hats[n+1] = e

	// c_hats[n+1] (for e)
	msgNTTe, err := pp.NewPolyCNTTFromCoeffs(msg_hats[n+1])
	if err != nil {
		return nil, err
	}
	c_hats[n+1] = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+2], r_hat, pp.paramLC),
		//&PolyCNTT{coeffs: msg_hats[n+1]},
		msgNTTe,
	)

	////	todo_done 2022.04.03: check the scope of u_p in theory
	////	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/12.
	////	As Bf should be bound by d_c J, so that |B f + e| < q_c/2, there should not be modular reduction.
	//betaF := pp.paramDC * J
	//	2023.12.1 Using the accurate bound
	betaF := (pp.paramN - 1) * (n - 1)
	boundF := pp.paramEtaF - int64(betaF)

	u_p := make([]int64, pp.paramDC)
	//u_p_tmp := make([]int64, pp.paramDC)

	seedMsg, err := pp.collectBytesForBalanceProofL0Rn(preMsg, vL, nR, cmtRs, b_hat, c_hats)
	if err != nil {
		return nil, err
	}

	seed_binM, err := Hash(seedMsg) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).

	if err != nil {
		return nil, err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return nil, err
	}
	// compute B f + e and check the normal
	for i := 0; i < pp.paramDC; i++ {
		//u_p_tmp[i] = e[i]
		u_p[i] = e[i]
		for j := 0; j < pp.paramDC; j++ {
			if (binM[i][j/8]>>(j%8))&1 == 1 {
				// u_p_tmp[i] = u_p_tmp[i] + f[j]
				u_p[i] = u_p[i] + f[j]
			}
		}

		//infNorm := u_p_tmp[i]
		infNorm := u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}
		if infNorm > boundF {
			goto balanceProofL0RnRestart
		}

		//			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo_done: 202203 Do need reduce? no.
	}

	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = u_p

	n1 := n
	rprlppi, pi_err := pp.rpulpProveMLP(preMsg, cmtRs, cmtrRs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, uint8(nR), 3, u_hats)

	if pi_err != nil {
		return nil, pi_err
	}

	return &BalanceProofLmRn{
		balanceProofCase: BalanceProofCaseLmRn,
		leftCommNum:      0,
		rightCommNum:     uint8(nR), // Note that nR has been checked previously, being smaller than paramJ
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil
}

// verifyBalanceProofL0Rn verifies BalanceProofL0Rn.
// todo: review
func (pp *PublicParameter) verifyBalanceProofL0Rn(preMsg []byte, vL uint64, outFoRing uint8, cmtRs []*ValueCommitment, balanceProof *BalanceProofLmRn) (bool, error) {
	if len(preMsg) == 0 {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1
	if vL > V {
		return false, nil
	}

	if outFoRing < 2 {
		return false, fmt.Errorf("verifyBalanceProofL0Rn: the input outFoRing should be >= 2")
	}

	nR := outFoRing
	n := int(outFoRing)
	if len(cmtRs) != n {
		return false, nil
	}

	for i := 0; i < n; i++ {
		cmt := cmtRs[i]
		if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
			return false, nil
		}
	}

	if balanceProof == nil {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseLmRn {
		return false, fmt.Errorf("verifyBalanceProofL0Rn: balanceProof.balanceProofCase is not BalanceProofCaseLmRn")
	}

	if balanceProof.leftCommNum != 0 || balanceProof.rightCommNum != outFoRing {
		return false, nil
	}

	if balanceProof.b_hat == nil || len(balanceProof.b_hat.polyCNTTs) != pp.paramK {
		return false, nil
	}

	n2 := n + 2
	if len(balanceProof.c_hats) != n2 {
		return false, nil
	}

	if len(balanceProof.u_p) != pp.paramDC {
		return false, nil
	}

	if balanceProof.rpulpproof == nil {
		return false, nil
	}

	//	infNorm of u'
	//	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/12.
	//	As Bf should be bound by (N-1) (n-1), so that |B f + e| < q_c/2, there should not be modular reduction.
	betaF := (pp.paramN - 1) * (n - 1)
	boundF := pp.paramEtaF - int64(betaF)
	infNorm := int64(0)
	for i := 0; i < pp.paramDC; i++ {
		infNorm = balanceProof.u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}

		if infNorm > boundF {
			return false, nil
		}
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0Rn(preMsg, vL, outFoRing, cmtRs, balanceProof.b_hat, balanceProof.c_hats)
	if err != nil {
		return false, err
	}
	seed_binM, err := Hash(seedMsg) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
	if err != nil {
		return false, err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return false, err
	}

	u_hats := make([][]int64, 3)

	u := pp.intToBinary(vL)
	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = balanceProof.u_p

	n1 := n
	flag := pp.rpulpVerifyMLP(preMsg, cmtRs, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, nR, 3, u_hats, balanceProof.rpulpproof)

	return flag, nil
}

// balanceProofL0R0SerializeSize returns the serialize size for balanceProofL0R0.
// reviewed on 2023.12.07
func (pp *PublicParameter) balanceProofL0R0SerializeSize() int {
	n := 1 // balanceProofCase BalanceProofCase
	return n
}

// serializeBalanceProofL0R0 serialize the input BalanceProofL0R0 to []byte.
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
func (pp *PublicParameter) balanceProofL0R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		HashOutputBytesLen + // chseed           []byte
		+pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofL0R1 serialize the input BalanceProofL0R1 to []byte.
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
func (pp *PublicParameter) balanceProofL1R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		pp.PolyCNTTSerializeSize() + //  psi              *PolyCNTT
		HashOutputBytesLen + // chseed           []byte
		+2*pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs1, zs2        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofLR1 serialize the input BalanceProofL1R1 to []byte.
// reviewed on 2023.12.07
func (pp *PublicParameter) serializeBalanceProofL1R1(bpf *BalanceProofL1R1) ([]byte, error) {

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
// reviewed on 2023.12.07
func (pp *PublicParameter) deserializeBalanceProofL1R1(serializedBpfL1R1 []byte) (*BalanceProofL1R1, error) {

	r := bytes.NewReader(serializedBpfL1R1)

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
// reviewed on 2023.12.07
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
	} else {
		// nL >= 2
		// A_{L2R2}
		n2 = n + 4 // m_{sum}, f_L, f_R, e
	}

	length = length + int(n2)*pp.PolyCNTTSerializeSize() + // c_hats           []*PolyCNTT, length n2
		pp.CarryVectorRProofSerializeSize() //	u_p              []int64	, dimension paramK, bounded \eta_f

	length = length + pp.rpulpProofMLPSerializeSizeByCommNum(nL, nR) //  rpulpproof       *RpulpProofMLP

	return length
}

// serializeBalanceProofLmRn serialize the input BalanceProofLmRn to []byte.
// reviewed on 2023.12.07
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
// reviewed on 2023.12.07
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
	serializedRpUlpProofBytes := make([]byte, pp.rpulpProofMLPSerializeSizeByCommNum(nL, nR))
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

//	helper functions	begin

// collectBytesForBalanceProofL0R1 collect bytes for genBalanceProofL0R1() and verifyBalanceProofL0R1().
// developed based on collectBytesForCoinbaseTxJ1()
// reviewed on 2023.12.07
func (pp *PublicParameter) collectBytesForBalanceProofL0R1(preMsg []byte, vL uint64, cmt *ValueCommitment, ws []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {
	length := len(preMsg) + 8 + pp.ValueCommitmentSerializeSize() +
		pp.paramK*(pp.paramKC+1)*pp.paramDC*8

	rst := make([]byte, 0, length)

	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	// preMsg
	rst = append(rst, preMsg...)

	// vL
	rst = append(rst, byte(vL>>0))
	rst = append(rst, byte(vL>>8))
	rst = append(rst, byte(vL>>16))
	rst = append(rst, byte(vL>>24))
	rst = append(rst, byte(vL>>32))
	rst = append(rst, byte(vL>>40))
	rst = append(rst, byte(vL>>48))
	rst = append(rst, byte(vL>>56))

	// cmt
	serializedCmt, err := pp.SerializeValueCommitment(cmt)
	if err != nil {
		return nil, err
	}
	rst = append(rst, serializedCmt...)

	// ws []*PolyCNTTVec
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyCNTTToBytes(ws[i].polyCNTTs[j])
		}
	}

	// deltas []*PolyCNTT
	for i := 0; i < len(deltas); i++ {
		appendPolyCNTTToBytes(deltas[i])
	}

	return rst, nil
}

// collectBytesForBalanceProofL0Rn is an auxiliary function for genBalanceProofL0Rn and verifyBalanceProofL0Rn to collect some information into a byte slice
// developed based on collectBytesForCoinbaseTxJ2()
// reviewed on 2023.12.07
func (pp *PublicParameter) collectBytesForBalanceProofL0Rn(preMsg []byte, vL uint64, nR uint8, cmts []*ValueCommitment, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(preMsg) + 8 + 1 + len(cmts)*pp.ValueCommitmentSerializeSize() +
		len(b_hat.polyCNTTs)*pp.paramDC*8 + len(c_hats)*pp.paramDC*8

	rst := make([]byte, 0, length)

	appendPolyCNTTToBytes := func(a *PolyCNTT) {
		for k := 0; k < pp.paramDC; k++ {
			rst = append(rst, byte(a.coeffs[k]>>0))
			rst = append(rst, byte(a.coeffs[k]>>8))
			rst = append(rst, byte(a.coeffs[k]>>16))
			rst = append(rst, byte(a.coeffs[k]>>24))
			rst = append(rst, byte(a.coeffs[k]>>32))
			rst = append(rst, byte(a.coeffs[k]>>40))
			rst = append(rst, byte(a.coeffs[k]>>48))
			rst = append(rst, byte(a.coeffs[k]>>56))
		}
	}

	// preMsg
	rst = append(rst, preMsg...)

	// vL
	rst = append(rst, byte(vL>>0))
	rst = append(rst, byte(vL>>8))
	rst = append(rst, byte(vL>>16))
	rst = append(rst, byte(vL>>24))
	rst = append(rst, byte(vL>>32))
	rst = append(rst, byte(vL>>40))
	rst = append(rst, byte(vL>>48))
	rst = append(rst, byte(vL>>56))

	// nR
	rst = append(rst, nR)

	// cmts
	for i := 0; i < len(cmts); i++ {
		serializedCmt, err := pp.SerializeValueCommitment(cmts[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmt...)
	}

	// b_hat
	for i := 0; i < len(b_hat.polyCNTTs); i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}

	// c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}

	return rst, nil
}

//	helper functions	end
