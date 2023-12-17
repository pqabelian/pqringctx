package pqringctx

import (
	"bytes"
	"fmt"
)

type BalanceProofCase uint8

const (
	BalanceProofCaseL0R0 BalanceProofCase = 0
	BalanceProofCaseL0R1 BalanceProofCase = 1
	BalanceProofCaseL0Rn BalanceProofCase = 2
	BalanceProofCaseL1R1 BalanceProofCase = 3
	BalanceProofCaseL1Rn BalanceProofCase = 4
	BalanceProofCaseLmRn BalanceProofCase = 5
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
	//	z1s and z2s, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	z1s []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	z2s []*PolyCVec //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
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

// genBalanceProofL0R0 generates a BalanceProofL0R0.
// reviewed on 2023.12.07
func (pp *PublicParameter) genBalanceProofL0R0() (*BalanceProofL0R0, error) {
	return &BalanceProofL0R0{
		balanceProofCase: BalanceProofCaseL0R0,
	}, nil
}

// verifyBalanceProofL0R0 verifies the input BalanceProofL0R0.
// reviewed on 2023.12.16
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
// reviewed on 2023.12.16
func (pp *PublicParameter) genBalanceProofL0R1(msg []byte, vL uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) (*BalanceProofL0R1, error) {
	// random from S_etaC^lc
	ys := make([]*PolyCNTTVec, pp.paramK)
	// w^t = B * y^t
	ws := make([]*PolyCNTTVec, pp.paramK)
	// delta = <h,y^t>
	deltas := make([]*PolyCNTT, pp.paramK)
	// z^t = y^t + sigma^t(c) * r_(out,j), r_(out,j) is from txoGen, in there, r_(out,j) is cmt_rs_j
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	zs := make([]*PolyCVec, pp.paramK)

genBalanceProofL0R1Restart:
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

	seedMsg, err := pp.collectBytesForBalanceProofL0R1Challenge(msg, vL, cmt, ws, deltas)
	if err != nil {
		return nil, err
	}

	chseed, err := Hash(seedMsg)
	if err != nil {
		return nil, err
	}

	boundC := pp.paramEtaC - int64(pp.paramBetaC)
	ch_poly, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ch_poly)
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
			goto genBalanceProofL0R1Restart
		}
	}

	return &BalanceProofL0R1{
		balanceProofCase: BalanceProofCaseL0R1,
		chseed:           chseed,
		zs:               zs,
	}, nil
}

// verifyBalanceProofL0R1 verifies BalanceProofL0R1.
// reviewed on 2023.12.16
// reviewed on 2023.12.17
func (pp *PublicParameter) verifyBalanceProofL0R1(msg []byte, vL uint64, cmt *ValueCommitment, balanceProof *BalanceProofL0R1) (bool, error) {
	if len(msg) == 0 {
		return false, nil
	}

	V := uint64(1)<<pp.paramN - 1
	if vL > V {
		return false, nil
	}

	if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
		return false, nil
	}
	for i := 0; i < len(cmt.b.polyCNTTs); i++ {
		if len(cmt.b.polyCNTTs[i].coeffs) != pp.paramDC {
			return false, nil
		}
	}
	if len(cmt.c.coeffs) != pp.paramDC {
		return false, nil
	}

	if balanceProof == nil || len(balanceProof.chseed) != HashOutputBytesLen || len(balanceProof.zs) != pp.paramK {
		return false, nil
	}
	for t := 0; t < pp.paramK; t++ {
		if len(balanceProof.zs[t].polyCs) != pp.paramLC {
			return false, nil
		}
		for i := 0; i < pp.paramLC; i++ {
			if len(balanceProof.zs[t].polyCs[i].coeffs) != pp.paramDC {
				return false, nil
			}
		}
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL0R1 {
		return false, fmt.Errorf("verifyBalanceProofL0R1: balanceProof.balanceProofCase is not BalanceProofCaseL0R1")
	}

	// infNorm of z^t
	bound := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
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

		z_ntt := pp.NTTPolyCVec(balanceProof.zs[t])

		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z_ntt, pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt.b, pp.paramKC),
			pp.paramKC,
		)
		deltas[t] = pp.PolyCNTTSub(
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], z_ntt, pp.paramLC),
			pp.PolyCNTTMul(
				sigma_t_ch,
				pp.PolyCNTTSub(cmt.c, msgNTT),
			),
		)
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0R1Challenge(msg, vL, cmt, ws, deltas)
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
// reviewed on 2023.12.16
func (pp *PublicParameter) genBalanceProofL0Rn(msg []byte, nR uint8, vL uint64, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRn, error) {

	n := int(nR)
	n2 := n + 2

	if n != len(cmtRs) || n != len(cmtrRs) || n != len(vRs) {
		return nil, fmt.Errorf("genBalanceProofL0Rn: The input cmtRs, cmtrRs, vRs should have the same length")
	}

	if n > pp.paramJ || n < 2 {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofL0Rn: the number of cmtRs (%d) is not in [2, %d]", n, pp.paramJ)
	}

	c_hats := make([]*PolyCNTT, n2)

	msg_hats := make([][]int64, n2)

	// msg_hats[0], ..., msg_hats[n-1]
	for j := uint8(0); j < nR; j++ {
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
	for j := uint8(0); j < nR; j++ {
		tmp = tmp + msg_hats[j][0]
	}
	f[0] = tmp >> 1

	// f[1], ..., f[d-2], f[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := uint8(0); j < nR; j++ {
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

genBalanceProofL0RnRestart:
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

	seedMsg, err := pp.collectBytesForBalanceProofL0RnChallenge(msg, nR, vL, cmtRs, b_hat, c_hats)
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

	u_p := make([]int64, pp.paramDC)
	//u_p_tmp := make([]int64, pp.paramDC)
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
			goto genBalanceProofL0RnRestart
		}

		//			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo_done: 202203 Do need reduce? no.
	}

	u_hats := make([][]int64, 3)

	u := pp.intToBinary(vL)
	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = u_p

	n1 := n
	rprlppi, pi_err := pp.rpulpProveMLP(msg, cmtRs, cmtrRs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, nR, 3, u_hats)

	if pi_err != nil {
		return nil, pi_err
	}

	return &BalanceProofLmRn{
		balanceProofCase: BalanceProofCaseL0Rn,
		leftCommNum:      0,
		rightCommNum:     nR,
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil
}

// verifyBalanceProofL0Rn verifies BalanceProofL0Rn.
// reviewed on 2023.12.16
// reviewed on 2023.12.17
func (pp *PublicParameter) verifyBalanceProofL0Rn(msg []byte, nR uint8, vL uint64, cmtRs []*ValueCommitment, balanceProof *BalanceProofLmRn) (bool, error) {
	if len(msg) == 0 {
		return false, nil
	}

	if nR < 2 || int(nR) > pp.paramJ {
		//	nope that pp.paramI = pp.paramJ
		return false, fmt.Errorf("verifyBalanceProofL0Rn: the input nR should be in [2, %d]", pp.paramJ)
	}

	V := uint64(1)<<pp.paramN - 1
	if vL > V {
		return false, nil
	}

	n := int(nR)
	if len(cmtRs) != n {
		return false, nil
	}

	for i := 0; i < n; i++ {
		cmt := cmtRs[i]
		if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
			return false, nil
		}
		for j := 0; j < pp.paramKC; j++ {
			if len(cmt.b.polyCNTTs[j].coeffs) != pp.paramDC {
				return false, nil
			}
		}
		if len(cmt.c.coeffs) != pp.paramDC {
			return false, nil
		}
	}

	if balanceProof == nil {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL0Rn {
		return false, fmt.Errorf("verifyBalanceProofL0Rn: balanceProof.balanceProofCase is not BalanceProofCaseL0Rn")
	}

	if balanceProof.leftCommNum != 0 || balanceProof.rightCommNum != nR {
		return false, nil
	}

	if balanceProof.b_hat == nil || len(balanceProof.b_hat.polyCNTTs) != pp.paramKC {
		return false, nil
	}

	for i := 0; i < pp.paramKC; i++ {
		if len(balanceProof.b_hat.polyCNTTs[i].coeffs) != pp.paramDC {
			return false, nil
		}
	}

	n2 := n + 2
	if len(balanceProof.c_hats) != n2 {
		return false, nil
	}
	for i := 0; i < n2; i++ {
		if len(balanceProof.c_hats[i].coeffs) != pp.paramDC {
			return false, nil
		}
	}

	if len(balanceProof.u_p) != pp.paramDC {
		return false, nil
	}

	if balanceProof.rpulpproof == nil {
		return false, nil
	}
	//	here we do not conduct sanity-check on balanceProof.rpulpproof,
	//	since that will be conducted by rpulpVerify.

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

	seedMsg, err := pp.collectBytesForBalanceProofL0RnChallenge(msg, nR, vL, cmtRs, balanceProof.b_hat, balanceProof.c_hats)
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
	flag := pp.rpulpVerifyMLP(msg, cmtRs, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, nR, 3, u_hats, balanceProof.rpulpproof)

	return flag, nil
}

// genBalanceProofL1R1 generates BalanceProofL1R1.
// reviewed on 2023.12.16
// todo: multi-round review
func (pp *PublicParameter) genBalanceProofL1R1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment,
	cmtr1 *PolyCNTTVec, cmtr2 *PolyCNTTVec, value uint64) (*BalanceProofL1R1, error) {

	y1s := make([]*PolyCNTTVec, pp.paramK)
	y2s := make([]*PolyCNTTVec, pp.paramK)

	w1s := make([]*PolyCNTTVec, pp.paramK)
	w2s := make([]*PolyCNTTVec, pp.paramK)
	deltas := make([]*PolyCNTT, pp.paramK)

genBalanceProofL1R1Restart:
	for t := 0; t < pp.paramK; t++ {
		//	y_1[t], y_2[t] \in (S_{eta_c})^{L_c}
		tmpY1, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		tmpY2, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		y1s[t] = pp.NTTPolyCVec(tmpY1)
		y2s[t] = pp.NTTPolyCVec(tmpY2)

		//	w_1[t] = B y_1[t], w_2[t] = B y_2[t], \delta[t] = <h, y_1[t]> - <h, y_2[t]>
		w1s[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y1s[t], pp.paramKC, pp.paramLC)
		w2s[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, y2s[t], pp.paramKC, pp.paramLC)
		deltas[t] = pp.PolyCNTTVecInnerProduct(
			pp.paramMatrixH[0],
			pp.PolyCNTTVecSub(y1s[t], y2s[t], pp.paramLC),
			pp.paramLC,
		)
	}

	// splicing the data to be processed
	preMsg, err := pp.collectBytesForBalanceProofL1R1Challenge1(msg, cmt1, cmt2, w1s, w2s, deltas)
	if err != nil {
		return nil, err
	}

	seed_rand, err := Hash(preMsg)
	if err != nil {
		return nil, err
	}

	//fmt.Println("prove seed_rand=", seed_rand)
	betas, err := pp.expandCombChallengeInBalanceProofL1R1(seed_rand)
	if err != nil {
		return nil, err
	}

	//	psi, psi'
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], cmtr1, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], y1s[0], pp.paramLC)

	msg_value := pp.intToBinary(value)
	msgNTT, err := pp.NewPolyCNTTFromCoeffs(msg_value)
	if err != nil {
		return nil, err
	}
	// 2 * m - mu
	TwoMSubMu := pp.PolyCNTTSub(
		//  m + m
		pp.PolyCNTTAdd(
			msgNTT,
			msgNTT,
		),
		pp.paramMu,
	)

	for t := 0; t < pp.paramK; t++ {
		// <h , y_1[t]>
		tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], y1s[t], pp.paramLC)

		// (2 * m - mu) <h, y_1[t]>
		tmp1 := pp.PolyCNTTMul(TwoMSubMu, tmp)

		//	(<h , y_1[t]>)^2
		tmp2 := pp.PolyCNTTMul(tmp, tmp)

		psi = pp.PolyCNTTSub(psi, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp1, t)))
		psip = pp.PolyCNTTAdd(psip, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp2, t)))
	}

	//	seed_ch and ch
	preMsgAll := pp.collectBytesForBalanceProofL1R1Challenge2(preMsg, psi, psip)
	chseed, err := Hash(preMsgAll)
	if err != nil {
		return nil, err
	}
	ch_ploy, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ch_ploy)

	//	z_1[t] = y_1[t] + sigma^t(c) * r_1
	//	z_2[t] = y_2[t] + sigma^t(c) * r_2
	z1s_ntt := make([]*PolyCNTTVec, pp.paramK)
	z2s_ntt := make([]*PolyCNTTVec, pp.paramK)
	z1s := make([]*PolyCVec, pp.paramK)
	z2s := make([]*PolyCVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)

		z1s_ntt[t] = pp.PolyCNTTVecAdd(y1s[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, cmtr1, pp.paramLC), pp.paramLC)
		z1s[t] = pp.NTTInvPolyCVec(z1s_ntt[t])
		if z1s[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto genBalanceProofL1R1Restart
		}

		z2s_ntt[t] = pp.PolyCNTTVecAdd(y2s[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, cmtr2, pp.paramLC), pp.paramLC)
		z2s[t] = pp.NTTInvPolyCVec(z2s_ntt[t])
		if z2s[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto genBalanceProofL1R1Restart
		}
	}

	return &BalanceProofL1R1{
		balanceProofCase: BalanceProofCaseL1R1,
		psi:              psi,
		chseed:           chseed,
		z1s:              z1s,
		z2s:              z2s,
	}, nil
}

// verifyBalanceProofL1R1 verifies BalanceProofL1R1.
// todo: multi-round review
func (pp *PublicParameter) verifyBalanceProofL1R1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment, balanceProof *BalanceProofL1R1) (bool, error) {

	if len(msg) == 0 {
		return false, nil
	}

	if cmt1 == nil || cmt1.b == nil || len(cmt1.b.polyCNTTs) != pp.paramKC || cmt1.c == nil {
		return false, nil
	}

	if cmt2 == nil || cmt2.b == nil || len(cmt2.b.polyCNTTs) != pp.paramKC || cmt2.c == nil {
		return false, nil
	}

	if balanceProof == nil || balanceProof.balanceProofCase != BalanceProofCaseL1R1 || balanceProof.psi == nil ||
		len(balanceProof.chseed) != HashOutputBytesLen ||
		len(balanceProof.z1s) != pp.paramK || len(balanceProof.z2s) != pp.paramK {
		return false, nil
	}

	bound := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
		if len(balanceProof.z1s[t].polyCs) != pp.paramLC || len(balanceProof.z2s[t].polyCs) != pp.paramLC {
			return false, nil
		}

		if balanceProof.z1s[t].infNorm() > bound {
			return false, nil
		}

		if balanceProof.z2s[t].infNorm() > bound {
			return false, nil
		}
	}

	ch_poly, err := pp.expandChallengeC(balanceProof.chseed)
	if err != nil {
		return false, nil
	}
	ch := pp.NTTPolyC(ch_poly)

	sigma_chs := make([]*PolyCNTT, pp.paramK)

	//	w1[t], w2[t]
	w1s := make([]*PolyCNTTVec, pp.paramK)
	w2s := make([]*PolyCNTTVec, pp.paramK)
	deltas := make([]*PolyCNTT, pp.paramK)

	z1s_ntt := make([]*PolyCNTTVec, pp.paramK)
	z2s_ntt := make([]*PolyCNTTVec, pp.paramK)

	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyCNTT(ch, t)

		z1s_ntt[t] = pp.NTTPolyCVec(balanceProof.z1s[t])
		w1s[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z1s_ntt[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], cmt1.b, pp.paramKC),
			pp.paramKC)

		z2s_ntt[t] = pp.NTTPolyCVec(balanceProof.z2s[t])
		w2s[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, z2s_ntt[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], cmt2.b, pp.paramKC),
			pp.paramKC)

		deltas[t] = pp.PolyCNTTSub(
			pp.PolyCNTTVecInnerProduct(
				pp.paramMatrixH[0],
				pp.PolyCNTTVecSub(z1s_ntt[t], z2s_ntt[t], pp.paramLC),
				pp.paramLC),
			pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(cmt1.c, cmt2.c)),
		)
	}

	// splicing the data to be processed
	preMsg, err := pp.collectBytesForBalanceProofL1R1Challenge1(msg, cmt1, cmt2, w1s, w2s, deltas)
	if err != nil {
		return false, err
	}

	seed_rand, err := Hash(preMsg)
	if err != nil {
		return false, err
	}

	//fmt.Println("prove seed_rand=", seed_rand)
	betas, err := pp.expandCombChallengeInBalanceProofL1R1(seed_rand)
	if err != nil {
		return false, err
	}

	// psi'
	psip := pp.NewZeroPolyCNTT()
	//mu := pp.paramMu
	for t := 0; t < pp.paramK; t++ {
		//	f_t = <h, z1_t> - sigma_c_t c_1
		f_t := pp.PolyCNTTSub(
			//	<h, z1_t>
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[0], z1s_ntt[t], pp.paramLC),
			//	sigma_c_t c_1
			pp.PolyCNTTMul(sigma_chs[t], cmt1.c),
		)
		//	tmp = f_t + sigma_c_t mu
		tmp := pp.PolyCNTTAdd(
			f_t,
			//	sigma_c_t mu
			pp.PolyCNTTMul(sigma_chs[t], pp.paramMu),
		)

		tmp = pp.PolyCNTTMul(tmp, f_t)
		tmp = pp.sigmaInvPolyCNTT(tmp, t)
		tmp = pp.PolyCNTTMul(betas[t], tmp)

		psip = pp.PolyCNTTAdd(psip, tmp)
	}

	psip = pp.PolyCNTTSub(psip, pp.PolyCNTTMul(ch, balanceProof.psi))
	psip = pp.PolyCNTTAdd(psip,
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], z1s_ntt[0], pp.paramLC))

	//	seed_ch and ch
	preMsgAll := pp.collectBytesForBalanceProofL1R1Challenge2(preMsg, balanceProof.psi, psip)
	chseed, err := Hash(preMsgAll)
	if err != nil {
		return false, err
	}

	if bytes.Compare(chseed, balanceProof.chseed) != 0 {
		return false, nil
	}

	return true, nil
}

// genBalanceProofL1Rn generates BalanceProofL1Rn.
// todo: multi-round review
func (pp *PublicParameter) genBalanceProofL1Rn(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, cmtrL *PolyCNTTVec, vL uint64, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRn, error) {

	nL := uint8(1)

	if int(nR) != len(cmtRs) || int(nR) != len(cmtrRs) || int(nR) != len(vRs) {
		return nil, fmt.Errorf("genBalanceProofL1Rn: The input cmtRs, cmtrRs, vRs should have the same length")
	}

	if int(nR) > pp.paramJ || nR < 2 {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofL1Rn: the number of cmtRs (%d) is not in [2, %d]", nR, pp.paramJ)
	}

	n := int(nL + nR)
	n2 := n + 2

	msg_hats := make([][]int64, n2)
	c_hats := make([]*PolyCNTT, n2)

	cmts := make([]*ValueCommitment, n)
	cmtrs := make([]*PolyCNTTVec, n)

	//	msg_hats[0]
	//	vL
	cmts[0] = cmtL
	cmtrs[0] = cmtrL
	msg_hats[0] = pp.intToBinary(vL)

	//	msg_hats[1], ..., msg_hats[n-1]
	//	vRs[0], ..., vRs[nR-1]
	for j := uint8(0); j < nR; j++ {
		cmts[1+j] = cmtRs[j]
		cmtrs[1+j] = cmtrRs[j]
		msg_hats[1+j] = pp.intToBinary(vRs[j])
	}

	//	msg_u: the binary representation of vRPub
	//	Note that the proof is for vL = vRs[0] + ... + vRs[nR-1] + vRPub
	u := pp.intToBinary(vRPub)

	//	msg_hats[n] := f
	//	f is the carry vector for m_1 + m_2 + ... + m_{n-1} + vRPub, in particular,
	// f[0] = (m_1[0] + ... + m_{n-1}[0] + u[0]      )/2
	// f[1] = (m_1[1] + ... + m_{n-1}[1] + u[1] + f[0])/2
	// ...
	// f[t] = (m_1[t] + ... + m_{n-1}[t] + u[t] + f[t-1])/2
	// ...
	// f[d-1] = (m_1[d-1] + ... + m_{n-1}[d-1] + u[d-1] + f[d-2])/2

	// that is,
	// f[0] = (m_1[0] + ... + m_{n-1}[0] + u[0]         )/2
	// for t = 1, ..., d-1
	// f[t] = (m_1[t] + ... + m_{n-1}[t] + u[t] + f[t-1])/2
	f := make([]int64, pp.paramDC)

	// f[0]
	tmp := int64(0)
	for j := uint8(0); j < nR; j++ {
		tmp = tmp + msg_hats[1+j][0]
	}
	f[0] = (tmp + u[0]) >> 1

	// f[1], ..., f[d-2], f[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := uint8(0); j < nR; j++ {
			tmp = tmp + msg_hats[1+j][t]
		}
		f[t] = (tmp + u[t] + f[t-1]) >> 1
	}

	msg_hats[n] = f

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

genBalanceProofL1RnRestart:
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
		msgNTTe,
	)

	seedMsg, err := pp.collectBytesForBalanceProofL1RnChallenge(msg, nR, cmtL, cmtRs, vRPub, b_hat, c_hats)
	if err != nil {
		return nil, err
	}

	seed_binM, err := Hash(seedMsg)

	if err != nil {
		return nil, err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return nil, err
	}

	//	u_p = B f + e, where e \in [-eta_f, eta_f], with eta_f < q_c/12.
	//	As Bf should be bound by betaF, so that |B f + e| < q_c/2, there should not be modular reduction.
	betaF := (pp.paramN - 1) * int(nR) // for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * int(nR-1)
	}
	boundF := pp.paramEtaF - int64(betaF)

	u_p := make([]int64, pp.paramDC)
	//u_p_tmp := make([]int64, pp.paramDC)

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
			goto genBalanceProofL1RnRestart
		}

		//			u_p[i] = reduceInt64(u_p_tmp[i], pp.paramQC) // todo_done: 202203 Do need reduce? no.
	}

	u_hats := make([][]int64, 3) //	for L1Rn, the rpulp matrix has m=3
	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = u_p

	n1 := n
	rprlppi, pi_err := pp.rpulpProveMLP(msg, cmts, cmtrs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeL1Rn, binM, 1, nR, 3, u_hats)

	if pi_err != nil {
		return nil, pi_err
	}

	return &BalanceProofLmRn{
		balanceProofCase: BalanceProofCaseL1Rn,
		leftCommNum:      1,
		rightCommNum:     nR,
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil

	return nil, nil
}

// verifyBalanceProofL1Rn verifies BalanceProofL1Rn.
// todo: multi-round view
func (pp *PublicParameter) verifyBalanceProofL1Rn(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, balanceProof *BalanceProofLmRn) (bool, error) {
	if len(msg) == 0 {
		return false, nil
	}

	//	Note that BalanceProofL1Rn could be
	//	(nR == 1 && vRPub > 0) || nR >= 2
	if int(nR) > pp.paramJ {
		//	Note that pp.paramI = pp.paramJ
		return false, nil
	}
	if nR == 0 {
		return false, nil
	}

	if nR == 1 && vRPub == 0 {
		return false, nil
	}

	if cmtL == nil || cmtL.b == nil || len(cmtL.b.polyCNTTs) != pp.paramKC || cmtL.c == nil {
		return false, nil
	}

	if len(cmtRs) != int(nR) {
		return false, nil
	}

	for i := uint8(0); i < nR; i++ {
		cmt := cmtRs[i]
		if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
			return false, nil
		}
	}

	V := uint64(1)<<pp.paramN - 1
	if vRPub > V {
		return false, nil
	}

	if balanceProof == nil {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL1Rn {
		return false, fmt.Errorf("verifyBalanceProofL1Rn: balanceProof.balanceProofCase is not BalanceProofCaseL1Rn")
	}

	if balanceProof.leftCommNum != 1 || balanceProof.rightCommNum != nR {
		return false, nil
	}

	if balanceProof.b_hat == nil || len(balanceProof.b_hat.polyCNTTs) != pp.paramKC {
		return false, nil
	}

	nL := uint8(1)
	n := int(nL + nR)
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

	betaF := (pp.paramN - 1) * int(nR) //	for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * int(nR-1)
	}

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

	seedMsg, err := pp.collectBytesForBalanceProofL1RnChallenge(msg, nR, cmtL, cmtRs, vRPub, balanceProof.b_hat, balanceProof.c_hats)
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
	u := pp.intToBinary(vRPub)
	u_hats[0] = u
	u_hats[1] = make([]int64, pp.paramDC)
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = 0
	}
	u_hats[2] = balanceProof.u_p

	cmts := make([]*ValueCommitment, n)
	cmts[0] = cmtL
	for j := uint8(0); j < nR; j++ {
		cmts[1+j] = cmtRs[j]
	}

	n1 := n
	flag := pp.rpulpVerifyMLP(msg, cmts, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeL1Rn, binM, 1, nR, 3, u_hats, balanceProof.rpulpproof)

	return flag, nil
}

// genBalanceProofLmRn generates BalanceProofLmRn.
// todo: multi-round review
func (pp *PublicParameter) genBalanceProofLmRn(msg []byte, nL uint8, nR uint8, cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, cmtrLs []*PolyCNTTVec, vLs []uint64, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRn, error) {

	if int(nL) != len(cmtLs) || int(nL) != len(cmtrLs) || int(nL) != len(vLs) {
		return nil, fmt.Errorf("genBalanceProofLmRn: The input cmtLs, cmtrLs, vLs should have the same length")
	}

	if int(nL) > pp.paramI || nL < 2 {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofLmRn: the number of cmtLs (%d) is not in [2, %d]", nL, pp.paramI)
	}

	if int(nR) != len(cmtRs) || int(nR) != len(cmtrRs) || int(nR) != len(vRs) {
		return nil, fmt.Errorf("genBalanceProofLmRn: The input cmtRs, cmtrRs, vRs should have the same length")
	}

	if int(nR) > pp.paramJ || nR < 2 {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofLmRn: the number of cmtRs (%d) is not in [2, %d]", nR, pp.paramJ)
	}

	n := int(nL + nR)
	n2 := n + 4

	msg_hats := make([][]int64, n2)
	c_hats := make([]*PolyCNTT, n2)

	cmts := make([]*ValueCommitment, n)
	cmtrs := make([]*PolyCNTTVec, n)

	//	Note that the proof is for vLs[0] + ... + vLs[nL-1] = vRs[0] + ... + vRs[nR-1] + vRPub.
	//  This is proved by vLs[0] + ... + vLs[nL-1] = vSum = vRs[0] + ... + vRs[nR-1] + vRPub.
	//	Note that the proof generation algorithm does not conduct sanity-check, as the verification will check and verify.
	vSum := uint64(0)

	//	msg_hats[0], ..., msg_hats[nL-1]
	//	vLs[0], ..., vLs[nL-1]
	for i := uint8(0); i < nL; i++ {
		cmts[i] = cmtLs[i]
		cmtrs[i] = cmtrLs[i]
		msg_hats[i] = pp.intToBinary(vLs[i])

		vSum += vLs[i]
	}

	//	msg_hats[nL], ..., msg_hats[nL+nR-1]
	//	vRs[0], ..., vRs[nR-1]
	for j := uint8(0); j < nR; j++ {
		cmts[nL+j] = cmtRs[j]
		cmtrs[nL+j] = cmtrRs[j]
		msg_hats[nL+j] = pp.intToBinary(vRs[j])
	}

	//	msg_hats[n]
	//	vSum = vLs[0] + ... + vLs[nL-1]
	msg_hats[n] = pp.intToBinary(vSum)

	//	msg_hats[n+1] := fL
	//	To prove vSum = vLs[0] + ... + vLs[nL-1], we compute
	//	fL, which is the carry vector for m_0 + m_2 + ... + m_{nL-1}, in particular,
	// fL[0] = (m_0[0] + ... + m_{nL-1}[0]      )/2
	// fL[1] = (m_0[1] + ... + m_{nL-1}[1] + fL[0])/2
	// ...
	// fL[t] = (m_0[t] + ... + m_{nL-1}[t] + fL[t-1])/2
	// ...
	// fL[d-1] = (m_0[d-1] + ... + m_{nL-1}[d-1] + fL[d-2])/2

	// that is,
	// fL[0] = (m_0[0] + ... + m_{nL-1}[0]         )/2
	// for t = 1, ..., d-1
	// fL[t] = (m_0[t] + ... + m_{nL-1}[t] + fL[t-1])/2
	fL := make([]int64, pp.paramDC)

	// fL[0]
	tmp := int64(0)
	for i := uint8(0); i < nL; i++ {
		tmp = tmp + msg_hats[i][0]
	}
	fL[0] = tmp >> 1

	// fL[1], ..., fL[d-2], f[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for i := uint8(0); i < nL; i++ {
			tmp = tmp + msg_hats[i][t]
		}
		fL[t] = (tmp + fL[t-1]) >> 1
	}

	msg_hats[n+1] = fL

	//	msg_u: the binary representation of vRPub
	//	Note that the proof is for vLs[0] + ... + vLs[nL-1] = vSum = vRs[0] + ... + vRs[nR-1] + vRPub
	u := pp.intToBinary(vRPub)

	//	msg_hats[n+2] := fR
	//	To prove vSum = vRs[0] + ... + vRs[nR-1] + vRPub, we compute
	//	fR, which is the carry vector for m_{nL} + m_{nL+1} + ... + m_{nL+nR-1} + vRPub, in particular,
	// fR[0] = (m_{nL}[0] + ... + m_{nL+nR-1}[0] + u[0]      )/2
	// fR[1] = (m_{nL}[1] + ... + m_{nL+nR-1}[1] + u[1] + fR[0])/2
	// ...
	// fR[t] = (m_{nL}[t] + ... + m_{nL+nR-1}[t] + u[t] + fR[t-1])/2
	// ...
	// fR[d-1] = (m_{nL}[d-1] + ... + m_{nL+nR-1}[d-1] + u[d-1] + fR[d-2])/2

	// that is,
	// fR[0] = (m_{nL}[0] + ... + m_{nL+nR-1}[0] + u[0]         )/2
	// for t = 1, ..., d-1
	// fR[t] = (m_{nL}[t] + ... + m_{nL+nR-1}[t] + u[t] + fR[t-1])/2
	fR := make([]int64, pp.paramDC)

	// fR[0]
	tmp = int64(0)
	for j := uint8(0); j < nR; j++ {
		tmp = tmp + msg_hats[nL+j][0]
	}
	fR[0] = (tmp + u[0]) >> 1

	// fR[1], ..., fR[d-2], fR[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := uint8(0); j < nR; j++ {
			tmp = tmp + msg_hats[nL+j][t]
		}
		fR[t] = (tmp + u[t] + fR[t-1]) >> 1
	}

	msg_hats[n+2] = fR

	r_hat_poly, err := pp.sampleValueCmtRandomness()
	if err != nil {
		return nil, err
	}
	r_hat := pp.NTTPolyCVec(r_hat_poly)

	// b_hat =B * r_hat
	b_hat := pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, r_hat, pp.paramKC, pp.paramLC)

	//	c_hats[0]~c_hats[n-1], c_hats[n] (for vSum), c_hats[n+1] (for fL), c_hats[n+2] (for fR)
	for i := 0; i < n+3; i++ {
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

genBalanceProofLmRnRestart:
	//e := make([]int64, pp.paramDC)
	e, err := pp.randomDcIntegersInQcEtaF()
	if err != nil {
		return nil, err
	}
	msg_hats[n+3] = e

	// c_hats[n+3] (for e)
	msgNTTe, err := pp.NewPolyCNTTFromCoeffs(msg_hats[n+3])
	if err != nil {
		return nil, err
	}
	c_hats[n+3] = pp.PolyCNTTAdd(
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[n+4], r_hat, pp.paramLC),
		msgNTTe,
	)

	seedMsg, err := pp.collectBytesForBalanceProofLmRnChallenge(msg, nL, nR, cmtLs, cmtRs, vRPub, b_hat, c_hats)
	if err != nil {
		return nil, err
	}

	seed_binM, err := Hash(seedMsg)

	if err != nil {
		return nil, err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
	if err != nil {
		return nil, err
	}

	//	u_p = B (fL || fR) + e, where e \in [-eta_f, eta_f], with eta_f < q_c/12.
	//	As B (fL || fR) should be bound by betaF, so that |B f + e| < q_c/2, there should not be modular reduction.
	betaF := (pp.paramN - 1) * int(nL-1+nR) // for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * int(nL-1+nR-1)
	}
	boundF := pp.paramEtaF - int64(betaF)

	u_p := make([]int64, pp.paramDC)
	//u_p_tmp := make([]int64, pp.paramDC)

	// compute u_p = B (fL || fR) + e and check the normal
	for i := 0; i < pp.paramDC; i++ {
		//u_p_temp[i] = e[i]
		u_p[i] = e[i]
		for j := 0; j < pp.paramDC; j++ {
			if (binM[i][j/8]>>(j%8))&1 == 1 {
				//u_p_temp[i] += fL[j]
				u_p[i] += fL[j]
			}
			if (binM[i][(pp.paramDC+j)/8]>>((pp.paramDC+j)%8))&1 == 1 {
				//u_p_temp[i] += fR[j]
				u_p[i] += fR[j]
			}
		}

		//infNorm := u_p_temp[i]
		infNorm := u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}

		if infNorm > boundF {
			goto genBalanceProofLmRnRestart
		}

		// u_p[i] = reduceInt64(u_p_temp[i], pp.paramQC) // todo_done: 2022.04.03 Do need reduce? no.
	}

	u_hats := make([][]int64, 5) //	for LmRn, the rpulp matrix will have m=5
	u_hats[0] = make([]int64, pp.paramDC)
	u_hats[1] = make([]int64, pp.paramDC) //	-u
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = -u[i]
	}
	u_hats[2] = make([]int64, pp.paramDC)
	u_hats[3] = make([]int64, pp.paramDC)
	u_hats[4] = u_p

	for i := 0; i < pp.paramDC; i++ {
		u_hats[0][i] = 0
		u_hats[2][i] = 0
		u_hats[3][i] = 0
	}

	n1 := n + 1 //	vSum needs to be proven in [0, V]

	rprlppi, pi_err := pp.rpulpProveMLP(msg, cmts, cmtrs, uint8(n), b_hat, r_hat, c_hats, msg_hats, uint8(n2), uint8(n1), RpUlpTypeLmRn, binM, nL, nR, 5, u_hats)

	if pi_err != nil {
		return nil, pi_err
	}

	return &BalanceProofLmRn{
		balanceProofCase: BalanceProofCaseLmRn,
		leftCommNum:      nL,
		rightCommNum:     nR,
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil

	return nil, nil
}

// verifyBalanceProofLmRn verifies BalanceProofLmRn.
// todo: multi-round review
func (pp *PublicParameter) verifyBalanceProofLmRn(msg []byte, nL uint8, nR uint8, cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, balanceProof *BalanceProofLmRn) (bool, error) {
	if len(msg) == 0 {
		return false, nil
	}

	if nL < 2 || int(nL) > pp.paramI {
		//	Note that pp.paramI = pp.paramJ
		return false, nil
	}

	//	Note that BalanceProofLmRn could be
	//	(nR == 1 && vRPub > 0) || nR >= 2
	if int(nR) > pp.paramJ {
		//	Note that pp.paramI = pp.paramJ
		return false, nil
	}
	if nR == 0 {
		return false, nil
	}
	if nR == 1 && vRPub == 0 {
		return false, nil
	}

	if len(cmtLs) != int(nL) {
		return false, nil
	}

	for i := uint8(0); i < nL; i++ {
		cmt := cmtLs[i]
		if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
			return false, nil
		}
	}

	if len(cmtRs) != int(nR) {
		return false, nil
	}

	for i := uint8(0); i < nR; i++ {
		cmt := cmtRs[i]
		if cmt == nil || cmt.b == nil || len(cmt.b.polyCNTTs) != pp.paramKC || cmt.c == nil {
			return false, nil
		}
	}

	V := uint64(1)<<pp.paramN - 1
	if vRPub > V {
		return false, nil
	}

	if balanceProof == nil {
		return false, nil
	}

	if balanceProof.balanceProofCase != BalanceProofCaseLmRn {
		return false, fmt.Errorf("verifyBalanceProofLmRn: balanceProof.balanceProofCase is not BalanceProofCaseLmRn")
	}

	if balanceProof.leftCommNum != nL || balanceProof.rightCommNum != nR {
		return false, nil
	}

	if balanceProof.b_hat == nil || len(balanceProof.b_hat.polyCNTTs) != pp.paramKC {
		return false, nil
	}

	n := int(nL + nR)
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

	betaF := (pp.paramN - 1) * int(nL-1+nR) // for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * int(nL-1+nR-1)
	}
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

	seedMsg, err := pp.collectBytesForBalanceProofLmRnChallenge(msg, nL, nR, cmtLs, cmtRs, vRPub, balanceProof.b_hat, balanceProof.c_hats)
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

	u_hats := make([][]int64, 5) //	for LmRn, the rpulp matrix will have m=5
	u := pp.intToBinary(vRPub)
	u_hats[0] = make([]int64, pp.paramDC)
	u_hats[1] = make([]int64, pp.paramDC) //	-u
	for i := 0; i < pp.paramDC; i++ {
		u_hats[1][i] = -u[i]
	}
	u_hats[2] = make([]int64, pp.paramDC)
	u_hats[3] = make([]int64, pp.paramDC)
	u_hats[4] = balanceProof.u_p

	for i := 0; i < pp.paramDC; i++ {
		u_hats[0][i] = 0
		u_hats[2][i] = 0
		u_hats[3][i] = 0
	}

	cmts := make([]*ValueCommitment, n)
	for i := uint8(0); i < nL; i++ {
		cmts[i] = cmtLs[i]
	}
	for j := uint8(0); j < nR; j++ {
		cmts[nL+j] = cmtRs[j]
	}

	n1 := n
	flag := pp.rpulpVerifyMLP(msg, cmts, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeLmRn, binM, nL, nR, 5, u_hats, balanceProof.rpulpproof)

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
		+2*pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // z1s, z2s        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
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

	//	z1s               []*PolyCVec
	//	fixed-length paramK
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, bpf.z1s[i])
		if err != nil {
			return nil, err
		}
	}

	//	z2s               []*PolyCVec
	//	fixed-length paramK
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, bpf.z2s[i])
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

	//	z1s               []*PolyCVec
	//	fixed-length paramK
	zs1 := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs1[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	//	z2s               []*PolyCVec
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
		z1s:              zs1,
		z2s:              zs2,
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

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseL0Rn &&
		BalanceProofCase(balanceProofCase) != BalanceProofCaseL1Rn &&
		BalanceProofCase(balanceProofCase) != BalanceProofCaseLmRn {
		return nil, fmt.Errorf("deserializeBalanceProofLmRn: the deserialized balanceProofCase is not BalanceProofCaseL0Rn, BalanceProofCaseL1Rn, or BalanceProofCaseLmRn")
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
		balanceProofCase: BalanceProofCase(balanceProofCase),
		leftCommNum:      leftCommNum,
		rightCommNum:     rightCommNum,
		b_hat:            b_hat,
		c_hats:           c_hats,
		u_p:              u_p,
		rpulpproof:       rpUlpProof,
	}, nil
}

//	helper functions	begin

// collectBytesForBalanceProofL0R1Challenge collect bytes for genBalanceProofL0R1() and verifyBalanceProofL0R1().
// developed based on collectBytesForCoinbaseTxJ1()
// reviewed on 2023.12.07
// reviewed on 2023.12.16
func (pp *PublicParameter) collectBytesForBalanceProofL0R1Challenge(msg []byte, vL uint64, cmt *ValueCommitment, ws []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {
	length := len(msg) + 8 + pp.ValueCommitmentSerializeSize() +
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

	// msg
	rst = append(rst, msg...)

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

// collectBytesForBalanceProofL0RnChallenge collects pre-message bytes for the challenge in genBalanceProofL0Rn.
// developed based on collectBytesForCoinbaseTxJ2()
// reviewed on 2023.12.07
// reviewed on 2023.12.16
func (pp *PublicParameter) collectBytesForBalanceProofL0RnChallenge(msg []byte, nR uint8, vL uint64, cmts []*ValueCommitment, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(msg) + 1 + 8 + len(cmts)*pp.ValueCommitmentSerializeSize() +
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

	// msg
	rst = append(rst, msg...)

	// nR
	rst = append(rst, nR)

	// vL
	rst = append(rst, byte(vL>>0))
	rst = append(rst, byte(vL>>8))
	rst = append(rst, byte(vL>>16))
	rst = append(rst, byte(vL>>24))
	rst = append(rst, byte(vL>>32))
	rst = append(rst, byte(vL>>40))
	rst = append(rst, byte(vL>>48))
	rst = append(rst, byte(vL>>56))

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

// collectBytesForBalanceProofL1R1Challenge1 collects pre-message bytes for the challenge 1 in genBalanceProofL1R1.
// reviewed on 2023.12.16
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofL1R1Challenge1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment, w1s []*PolyCNTTVec, w2s []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {

	length := len(msg) + //	msg []byte
		2*pp.ValueCommitmentSerializeSize() + //	cmtL *ValueCommitment, cmtR *ValueCommitment
		2*pp.paramK*pp.paramKC*pp.paramDC*8 + //	w1s []*PolyCNTTVec, w2s []*PolyCNTTVec		dimension[K][Ka]
		pp.paramK*pp.paramDC*8 //	deltas []*PolyCNTT

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

	//	msg []byte
	rst = append(rst, msg...)

	//	cmt1 *ValueCommitment
	serializedCmt1, err := pp.SerializeValueCommitment(cmt1)
	if err != nil {
		return nil, err
	}
	rst = append(rst, serializedCmt1...)

	//	cmt2 *ValueCommitment
	serializedCmt2, err := pp.SerializeValueCommitment(cmt2)
	if err != nil {
		return nil, err
	}
	rst = append(rst, serializedCmt2...)

	//	w1s []*PolyCNTTVec
	for i := 0; i < len(w1s); i++ {
		for j := 0; j < len(w1s[i].polyCNTTs); j++ {
			appendPolyCNTTToBytes(w1s[i].polyCNTTs[j])
		}
	}

	//	w2s []*PolyCNTTVec
	for i := 0; i < len(w2s); i++ {
		for j := 0; j < len(w2s[i].polyCNTTs); j++ {
			appendPolyCNTTToBytes(w2s[i].polyCNTTs[j])
		}
	}

	//	deltas
	for i := 0; i < len(deltas); i++ {
		appendPolyCNTTToBytes(deltas[i])
	}

	return rst, nil
}

// expandCombChallengeInBalanceProofL1R1 generates paramK R_{q_c} elements from a random seed.
// reviewed on 2023.12.16
// todo: multi-round review
func (pp *PublicParameter) expandCombChallengeInBalanceProofL1R1(seed []byte) (betas []*PolyCNTT, err error) {

	// check the length of seed
	if len(seed) == 0 {
		return nil, fmt.Errorf("expandCombChallengeInBalanceProofL1R1: seed is empty")
	}

	// betas
	betas = make([]*PolyCNTT, pp.paramK)

	betaSeed := append([]byte{'B'}, seed...)
	tmpSeedLen := len(betaSeed) + 1 //	1 byte for index in [0, paramK]
	tmpSeed := make([]byte, tmpSeedLen)
	for i := 0; i < pp.paramK; i++ {
		copy(tmpSeed, betaSeed)
		tmpSeed[tmpSeedLen-1] = byte(i)
		//tmpSeed = append(tmpSeed, byte(i))
		coeffs, err := pp.randomDcIntegersInQc(tmpSeed)
		if err != nil {
			return nil, err
		}
		betas[i] = &PolyCNTT{coeffs}
	}

	return betas, nil
}

// collectBytesForBalanceProofL1R1Challenge2 collects pre-message bytes for the challenge 2 in genBalanceProofL1R1.
// reviewed on 2023.12.16
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofL1R1Challenge2(preMsg []byte,
	psi *PolyCNTT, psip *PolyCNTT) []byte {

	length := len(preMsg) + 2*pp.paramDC*8

	rst := make([]byte, 0, length)

	appendPolyNTTToBytes := func(a *PolyCNTT) {
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

	//	preMsg []byte
	rst = append(rst, preMsg...)

	// psi
	appendPolyNTTToBytes(psi)

	// psip
	appendPolyNTTToBytes(psip)

	return rst
}

// collectBytesForBalanceProofL1RnChallenge collects pre-message bytes for the challenge in genBalanceProofL1Rn.
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofL1RnChallenge(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(msg) + 1 + (1+int(nR))*pp.ValueCommitmentSerializeSize() + 8 +
		pp.paramKC*pp.paramDC*8 + len(c_hats)*pp.paramDC*8

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

	//	msg
	rst = append(rst, msg...)

	//	nR
	rst = append(rst, nR)

	//	cmtL
	serializedCmtL, err := pp.SerializeValueCommitment(cmtL)
	if err != nil {
		return nil, err
	}
	rst = append(rst, serializedCmtL...)

	// cmtRs
	for i := 0; i < len(cmtRs); i++ {
		serializedCmtR, err := pp.SerializeValueCommitment(cmtRs[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmtR...)
	}

	// vRPub
	rst = append(rst, byte(vRPub>>0))
	rst = append(rst, byte(vRPub>>8))
	rst = append(rst, byte(vRPub>>16))
	rst = append(rst, byte(vRPub>>24))
	rst = append(rst, byte(vRPub>>32))
	rst = append(rst, byte(vRPub>>40))
	rst = append(rst, byte(vRPub>>48))
	rst = append(rst, byte(vRPub>>56))

	//	b_hat
	for i := 0; i < len(b_hat.polyCNTTs); i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}

	//	c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}

	return rst, nil
}

// collectBytesForBalanceProofLmRnChallenge collects pre-message bytes for the challenge in genBalanceProofLmRn.
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofLmRnChallenge(msg []byte, nL uint8, nR uint8,
	cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(msg) + 2 +
		(int(nL+nR))*pp.ValueCommitmentSerializeSize() + 8 +
		pp.paramKC*pp.paramDC*8 + len(c_hats)*pp.paramDC*8

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

	//	msg
	rst = append(rst, msg...)

	//	nL
	rst = append(rst, nL)

	//	nR
	rst = append(rst, nR)

	//	cmtLs
	for i := 0; i < len(cmtLs); i++ {
		serializedCmtL, err := pp.SerializeValueCommitment(cmtLs[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmtL...)
	}

	// cmtRs
	for i := 0; i < len(cmtRs); i++ {
		serializedCmtR, err := pp.SerializeValueCommitment(cmtRs[i])
		if err != nil {
			return nil, err
		}
		rst = append(rst, serializedCmtR...)
	}

	// vRPub
	rst = append(rst, byte(vRPub>>0))
	rst = append(rst, byte(vRPub>>8))
	rst = append(rst, byte(vRPub>>16))
	rst = append(rst, byte(vRPub>>24))
	rst = append(rst, byte(vRPub>>32))
	rst = append(rst, byte(vRPub>>40))
	rst = append(rst, byte(vRPub>>48))
	rst = append(rst, byte(vRPub>>56))

	//	b_hat
	for i := 0; i < len(b_hat.polyCNTTs); i++ {
		appendPolyCNTTToBytes(b_hat.polyCNTTs[i])
	}

	//	c_hats
	for i := 0; i < len(c_hats); i++ {
		appendPolyCNTTToBytes(c_hats[i])
	}

	return rst, nil
}

//	helper functions	end
