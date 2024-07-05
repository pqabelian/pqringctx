package pqringctx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
// reviewed by Alice, 2024.07.02
type BalanceProof interface {
	BalanceProofCase() BalanceProofCase
}

// BalanceProofL0R0 is for the case where there are no commitments, so that the balance proof is actually empty.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.02
type BalanceProofL0R0 struct {
	balanceProofCase BalanceProofCase
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.02
func (bpf *BalanceProofL0R0) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL0R1 is for the case of v = cmt.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.02
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
// reviewed by Alice, 2024.07.02
func (bpf *BalanceProofL0R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofL1R1 is for the case of cmt1 = cmt2
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.02
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
// reviewed by Alice, 2024.07.02
func (bpf *BalanceProofL1R1) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// BalanceProofLmRnGeneral covers the cases where rpulpProof has to be used, including
// L0Rn:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0
// L1R1A: cmtL = cmtR + vRPub, where vRPub > 0
// L1Rn:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// LmR1A: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// LmRn:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
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
// For self-contained, (leftCommNum, rightCommNum, vRPub) are contained in the structure.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.03
type BalanceProofLmRnGeneral struct {
	balanceProofCase BalanceProofCase
	nL               uint8  //	leftCommNum
	nR               uint8  //	rightCommNum
	vRPub            uint64 //	To make the sanity-check strict, say the consistence of balanceProofCase
	// bpf
	b_hat      *PolyCNTTVec // with vector size K_c
	c_hats     []*PolyCNTT  // length n_2, which is determined by (leftCommNum, rightCommNum).
	u_p        []int64      // carry vector range proof, length paramDc, each lies in scope [-(eta_f-beta_f), (eta_f-beta_f)], where beta_f depends on (nL, nR).
	rpulpproof *RpulpProofMLP
}

// BalanceProofCase is a method that must be implemented to implement the interface BalanceProof.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.03
func (bpf *BalanceProofLmRnGeneral) BalanceProofCase() BalanceProofCase {
	return bpf.balanceProofCase
}

// genBalanceProofL0R0 generates a BalanceProofL0R0.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.03
func (pp *PublicParameter) genBalanceProofL0R0() (*BalanceProofL0R0, error) {
	return &BalanceProofL0R0{
		balanceProofCase: BalanceProofCaseL0R0,
	}, nil
}

// verifyBalanceProofL0R0 verifies the input BalanceProofL0R0.
// reviewed on 2023.12.16
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// reviewed by Alice, 2024.07.03
func (pp *PublicParameter) verifyBalanceProofL0R0(balanceProof *BalanceProofL0R0) error {
	if balanceProof == nil {
		return fmt.Errorf("verifyBalanceProofL0R0: the input BalanceProofL0R0 is nil")
	}

	if balanceProof.balanceProofCase != BalanceProofCaseL0R0 {
		return fmt.Errorf("verifyBalanceProofL0R0:  balanceProof.balanceProofCase (%d) != BalanceProofCaseL0R0", balanceProof.balanceProofCase)
	}

	return nil
}

// genBalanceProofL0R1 generates BalanceProofL0R1, proving vL = cmt.
// This is almost identical to J == 1 case of pqringct.coinbaseTxGen.
// reviewed on 2023.12.07
// reviewed on 2023.12.16
// reviewed by Alice, 2024.07.03
func (pp *PublicParameter) genBalanceProofL0R1(msg []byte, vL uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) (*BalanceProofL0R1, error) {
	//	sanity-checks	begin
	if len(msg) == 0 {
		return nil, fmt.Errorf("genBalanceProofL0R1: the input msg []byte is nil/empty")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vL > V {
		return nil, fmt.Errorf("genBalanceProofL0R1: the input vL uint64 is not in the allowed scope")
	}

	vLBinary := pp.intToBinary(vL)
	mNTT := &PolyCNTT{coeffs: vLBinary}
	if !pp.ValueCommitmentOpen(cmt, mNTT, cmtr, 0) {
		return nil, fmt.Errorf("genBalanceProofL0R1: the input (vL uint64, cmt *ValueCommitment, cmtr *PolyCNTTVec) does not match")
	}
	//	sanity-checks	end

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
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.03
func (pp *PublicParameter) verifyBalanceProofL0R1(msg []byte, vL uint64, cmt *ValueCommitment, balanceProof *BalanceProofL0R1) error {
	if len(msg) == 0 {
		return fmt.Errorf("verifyBalanceProofL0R1: the input msg is nil/empty")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vL > V {
		return fmt.Errorf("verifyBalanceProofL0R1: the input vL(%v) exceeds the allowed maximum value (%v)", vL, V)
	}

	if !pp.ValueCommitmentSanityCheck(cmt) {
		return fmt.Errorf("verifyBalanceProofL0R1: the input cmt *ValueCommitment is not well-from")
	}

	if !pp.BalanceProofL0R1SanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofL0R1: the input balanceProof *BalanceProofL0R1 is not well-from")
	}

	ws := make([]*PolyCNTTVec, pp.paramK)
	deltas := make([]*PolyCNTT, pp.paramK)

	ch_poly, err := pp.expandChallengeC(balanceProof.chseed)
	if err != nil {
		return err
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
		return err
	}
	seed_ch, err := Hash(seedMsg)
	if err != nil {
		return err
	}

	if bytes.Compare(seed_ch, balanceProof.chseed) != 0 {
		return fmt.Errorf("verifyBalanceProofL0R1: the computed seed_ch is different from balanceProof.chseed")
	}

	return nil

}

// genBalanceProofL0Rn generates genBalanceProofL0Rn, proving vL = cmts[0] + ... + cmts[nR-1].
// This is almost identical to J >= 2 case of pqringct.coinbaseTxGen.
// Note that this proving algorithm does not check the sanity of the inputs, since we need the corresponding verifying algorithm to guarantee the security.
// reviewed on 2023.12.07
// reviewed on 2023.12.16
// refactored and reviewed by Alice, 2024.07.03
func (pp *PublicParameter) genBalanceProofL0Rn(msg []byte, nR uint8, vL uint64, cmtRs []*ValueCommitment, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRnGeneral, error) {

	//	Sanity-Checks	begin
	if len(msg) == 0 {
		return nil, fmt.Errorf("genBalanceProofL0Rn: The input msg []byte is not well-form")
	}

	if nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofL0Rn: the input nR (%d) exceeding the allowed maximum %d", nR, pp.paramJ)
	}

	if nR < 2 {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofL0Rn: the input nR (%d) samller than 2", nR)
	}

	n := int(nR)
	n2 := n + 2

	if n2 > 0xFF {
		return nil, fmt.Errorf("genBalanceProofL0Rn: n2 = nR + 2 > 0xFF")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vL > V {
		return nil, fmt.Errorf("genBalanceProofL0Rn: the input vL uint64 is not in the allowed scope")
	}

	if len(cmtRs) != n || len(cmtrRs) != n || len(vRs) != n {
		return nil, fmt.Errorf("genBalanceProofL0Rn: The input (nR, cmtRs, cmtrRs, vRs) does not match")
	}

	//	Sanity-Checks	end

	c_hats := make([]*PolyCNTT, n2)

	msg_hats := make([][]int64, n2)

	// msg_hats[0], ..., msg_hats[n-1]
	for j := uint8(0); j < nR; j++ {
		if vRs[j] > V {
			return nil, fmt.Errorf("genBalanceProofL0Rn: the input vRs[%d] is not in the allowed scope", j)
		}

		msg_hats[j] = pp.intToBinary(vRs[j])

		msgjNTT, err := pp.NewPolyCNTTFromCoeffs(msg_hats[j])
		if err != nil {
			return nil, err
		}
		if !pp.ValueCommitmentOpen(cmtRs[j], msgjNTT, cmtrRs[j], 0) {
			return nil, fmt.Errorf("genBalanceProofL0Rn: The input (cmtRs, cmtrRs, vRs) does not match")
		}
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

	return &BalanceProofLmRnGeneral{
		balanceProofCase: BalanceProofCaseL0Rn,
		nL:               0,
		nR:               nR,
		vRPub:            0, //	This is fixed by rule.
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
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.03
func (pp *PublicParameter) verifyBalanceProofL0Rn(msg []byte, nR uint8, vL uint64, cmtRs []*ValueCommitment, balanceProof *BalanceProofLmRnGeneral) error {
	//	sanity-checks	begin
	if len(msg) == 0 {
		return fmt.Errorf("verifyBalanceProofL0Rn: the input msg is nil/empty")
	}

	if nR < 2 || nR > pp.paramJ {
		//	nope that pp.paramI = pp.paramJ
		return fmt.Errorf("verifyBalanceProofL0Rn: the input nR should be in [2, %d]", pp.paramJ)
	}

	n := int(nR)
	n2 := n + 2
	if n2 > 0xFF {
		return fmt.Errorf("verifyBalanceProofL0Rn: n2 = nR + 2 > 0xFF")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vL > V {
		return fmt.Errorf("verifyBalanceProofL0Rn: the input vL (%v) exceeds the allowed maximum value (%v)", vL, V)
	}

	if len(cmtRs) != n {
		return fmt.Errorf("verifyBalanceProofL0Rn: len(cmtRs) (%d) != nR (%d)", len(cmtRs), nR)
	}
	for i := 0; i < n; i++ {
		if !pp.ValueCommitmentSanityCheck(cmtRs[i]) {
			return fmt.Errorf("verifyBalanceProofL0Rn: the input cmtRs[%d] is not well-form", i)
		}
	}

	if !pp.BalanceProofL0RnSanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofL0Rn: the input balanceProof *BalanceProofLmRn is not well-form")
	}

	if balanceProof.nL != 0 || balanceProof.nR != nR || balanceProof.vRPub != 0 {
		return fmt.Errorf("verifyBalanceProofL0Rn: balanceProof.nL (%d) != 0 || balanceProof.nR (%d) != nR (%d) || balanceProof.vRPub (%v) != 0", balanceProof.nL, balanceProof.nR, nR, balanceProof.vRPub)
	}
	//	sanity-checks	end

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
			return fmt.Errorf("verifyBalanceProofL0Rn: balanceProof.u_p[%d] (%v) is not in the expected range", i, balanceProof.u_p[i])
		}
	}

	seedMsg, err := pp.collectBytesForBalanceProofL0RnChallenge(msg, nR, vL, cmtRs, balanceProof.b_hat, balanceProof.c_hats)
	if err != nil {
		return err
	}
	seed_binM, err := Hash(seedMsg) // todo_DONE: compute the seed using hash function on (b_hat, c_hats).
	if err != nil {
		return err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return err
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
	err = pp.rpulpVerifyMLP(msg, cmtRs, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeL0Rn, binM, 0, nR, 3, u_hats, balanceProof.rpulpproof)
	if err != nil {
		return err
	}

	return nil
}

// genBalanceProofL1R1 generates BalanceProofL1R1.
// reviewed on 2023.12.16
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.04
// todo: review by 2024.07
func (pp *PublicParameter) genBalanceProofL1R1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment,
	cmtr1 *PolyCNTTVec, cmtr2 *PolyCNTTVec, value uint64) (*BalanceProofL1R1, error) {

	//	sanity-checks	begin
	if len(msg) == 0 {
		return nil, fmt.Errorf("genBalanceProofL1R1: the input msg []byte is nil/empty")
	}

	V := (uint64(1) << pp.paramN) - 1
	if value > V {
		return nil, fmt.Errorf("genBalanceProofL1R1: the input value uint64 (%v) in not in the allowed scope (%v)", value, V)
	}

	valueBinary := pp.intToBinary(value)
	mNTT, err := pp.NewPolyCNTTFromCoeffs(valueBinary)
	if err != nil {
		return nil, err
	}
	if !pp.ValueCommitmentOpen(cmt1, mNTT, cmtr1, 0) {
		return nil, fmt.Errorf("genBalanceProofL1R1: the input (cmt1 *ValueCommitment, cmtr1 *PolyCNTTVec, value) does not match")
	}
	if !pp.ValueCommitmentOpen(cmt2, mNTT, cmtr2, 0) {
		return nil, fmt.Errorf("genBalanceProofL1R1: the input (cmt2 *ValueCommitment, cmtr2 *PolyCNTTVec, value) does not match")
	}
	//	sanity-checks	end

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
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[int(pp.paramI)+int(pp.paramJ)+6], cmtr1, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[int(pp.paramI)+int(pp.paramJ)+6], y1s[0], pp.paramLC)

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

	bound := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)

		z1s_ntt[t] = pp.PolyCNTTVecAdd(y1s[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, cmtr1, pp.paramLC), pp.paramLC)
		z1s[t] = pp.NTTInvPolyCVec(z1s_ntt[t])
		if z1s[t].infNorm() > bound {
			goto genBalanceProofL1R1Restart
		}

		z2s_ntt[t] = pp.PolyCNTTVecAdd(y2s[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, cmtr2, pp.paramLC), pp.paramLC)
		z2s[t] = pp.NTTInvPolyCVec(z2s_ntt[t])
		if z2s[t].infNorm() > bound {
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
// reviewed on 2023.12.18
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// todo: multi-round review
// refactored and reviewed by Alice, 2024.07.04
// todo: review by 2024.07
func (pp *PublicParameter) verifyBalanceProofL1R1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment, balanceProof *BalanceProofL1R1) error {

	//	sanity-checks	begin
	if len(msg) == 0 {
		return fmt.Errorf("verifyBalanceProofL1R1: the input msg []byte is nil/empty")
	}

	if !pp.ValueCommitmentSanityCheck(cmt1) {
		return fmt.Errorf("verifyBalanceProofL1R1: the input cmt1 is not well-form")
	}

	if !pp.ValueCommitmentSanityCheck(cmt2) {
		return fmt.Errorf("verifyBalanceProofL1R1: the input cmt2 is not well-form")
	}

	if !pp.BalanceProofL1R1SanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofL1R1: the input balanceProof *BalanceProofL1R1 is not well-form")
	}
	//	sanity-checks	end

	ch_poly, err := pp.expandChallengeC(balanceProof.chseed)
	if err != nil {
		return err
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
		return err
	}

	seed_rand, err := Hash(preMsg)
	if err != nil {
		return err
	}

	//fmt.Println("prove seed_rand=", seed_rand)
	betas, err := pp.expandCombChallengeInBalanceProofL1R1(seed_rand)
	if err != nil {
		return err
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
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[int(pp.paramI)+int(pp.paramJ)+6], z1s_ntt[0], pp.paramLC))

	//	seed_ch and ch
	preMsgAll := pp.collectBytesForBalanceProofL1R1Challenge2(preMsg, balanceProof.psi, psip)
	chseed, err := Hash(preMsgAll)
	if err != nil {
		return err
	}

	if bytes.Compare(chseed, balanceProof.chseed) != 0 {
		return fmt.Errorf("verifyBalanceProofL1R1: the computed chseed is different from balanceProof.chseed")
	}

	return nil
}

// genBalanceProofL1Rn generates BalanceProofL1Rn, for the cases
// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// todo: multi-round review
// refactored and reviewed by Alice, 2024.07.04
// todo: review by 2024.07
func (pp *PublicParameter) genBalanceProofL1Rn(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, cmtrL *PolyCNTTVec, vL uint64, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRnGeneral, error) {

	//	sanity-checks	begin
	if len(msg) == 0 {
		return nil, fmt.Errorf("genBalanceProofL1Rn: The input msg []byte is empty/nil")
	}

	nL := uint8(1)

	V := (uint64(1) << pp.paramN) - 1
	if vRPub > V {
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input vRPub uint64 (%v) exceeds the allowed maximum value (%v)", vRPub, V)
	}

	if nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input nR uint8 (%d) exceeds the allowed maximum value (%d)", nR, pp.paramJ)
	}

	if nR == 0 {
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input nR is 0")
	}

	if nR == 1 {
		if vRPub == 0 {
			return nil, fmt.Errorf("genBalanceProofL1Rn: the input nR is 1 while vRPub = 0")
		} else {
			// do nothing, since this case is
			// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
		}
	} else {
		// do nothing, since this case is
		// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
	}

	n := int(nL) + int(nR)
	n2 := n + 2
	if n2 > 0xFF {
		return nil, fmt.Errorf("genBalanceProofL1Rn: n2 = 1 + nR > 0xFF")
	}

	if len(cmtRs) != int(nR) || len(cmtrRs) != int(nR) || len(vRs) != int(nR) {
		return nil, fmt.Errorf("genBalanceProofL1Rn: The input (nR, cmtRs, cmtrRs, vRs) does not match")
	}

	if vL > V {
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input vL uint64 (%v) exceeds the allowed maximum value (%v)", vL, V)
	}

	msg_hats := make([][]int64, n2)
	c_hats := make([]*PolyCNTT, n2)

	cmts := make([]*ValueCommitment, n)
	cmtrs := make([]*PolyCNTTVec, n)

	//	msg_hats[0]
	//	vL
	cmts[0] = cmtL
	cmtrs[0] = cmtrL
	msg_hats[0] = pp.intToBinary(vL)

	vLNTT, err := pp.NewPolyCNTTFromCoeffs(msg_hats[0])
	if err != nil {
		return nil, err
	}
	if !pp.ValueCommitmentOpen(cmtL, vLNTT, cmtrL, 0) {
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input (cmtL *ValueCommitment, cmtrL *PolyCNTTVec, vL uint64) does not match with each other")
	}

	vRSum := vRPub // for sanity-check
	//	msg_hats[1], ..., msg_hats[n-1]
	//	vRs[0], ..., vRs[nR-1]
	for j := uint8(0); j < nR; j++ {
		//	sanity-check	begin
		if vRs[j] > V {
			return nil, fmt.Errorf("genBalanceProofL1Rn: the input vRs[%d] (%v) exceeds the allowed maximum value (%v)", j, vRs[j], V)
		}
		vRSum = vRSum + vRs[j] // there will be no overflow at this point.
		if vRSum > vL {
			return nil, fmt.Errorf("genBalanceProofL1Rn: the sum of vRPub and the first vRs[%d] (%v) exceeds the value on the left side (%v)", j, vRs[j], vL)
		}

		cmts[1+j] = cmtRs[j]
		cmtrs[1+j] = cmtrRs[j]
		msg_hats[1+j] = pp.intToBinary(vRs[j])

		vRjNTT, err := pp.NewPolyCNTTFromCoeffs(msg_hats[1+j])
		if err != nil {
			return nil, err
		}
		if !pp.ValueCommitmentOpen(cmtRs[j], vRjNTT, cmtrRs[j], 0) {
			return nil, fmt.Errorf("genBalanceProofL1Rn: the input (cmtL *ValueCommitment, cmtrL *PolyCNTTVec, vL uint64) does not match with each other")
		}
	}

	if vRSum != vL {
		return nil, fmt.Errorf("genBalanceProofL1Rn: the input (vL uint64, vRPub uint64, vRs []uint64) does not match")
	}
	//	sanity-checks	end

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
		betaF = (pp.paramN - 1) * (int(nR) - 1)
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

	return &BalanceProofLmRnGeneral{
		balanceProofCase: BalanceProofCaseL1Rn,
		nL:               1,
		nR:               nR,
		vRPub:            vRPub,
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil

	return nil, nil
}

// verifyBalanceProofL1Rn verifies BalanceProofL1Rn.
// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.04
// todo: multi-round view
func (pp *PublicParameter) verifyBalanceProofL1Rn(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, balanceProof *BalanceProofLmRnGeneral) error {

	//	sanity-checks 	begin
	if len(msg) == 0 {
		return fmt.Errorf("verifyBalanceProofL1Rn: the input msg []byte is nil/empty")
	}

	nL := uint8(1)

	V := (uint64(1) << pp.paramN) - 1
	if vRPub > V {
		return fmt.Errorf("verifyBalanceProofL1Rn: the input vRPub uint64 (%v) exceeds the allowed maximum value (%v)", vRPub, V)
	}

	if nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return fmt.Errorf("verifyBalanceProofL1Rn: the input nR uint8 (%d) exceeds the allowed maximum value (%d)", nR, pp.paramJ)
	}

	if nR == 0 {
		return fmt.Errorf("verifyBalanceProofL1Rn: the input nR is 0")
	}

	if nR == 1 {
		if vRPub == 0 {
			return fmt.Errorf("verifyBalanceProofL1Rn: the input nR is 1 while vRPub = 0")
		} else {
			// do nothing, since this case is
			// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
		}
	} else {
		// do nothing, since this case is
		// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
	}

	n := int(nL) + int(nR)
	n2 := n + 2
	if n2 > 0xFF {
		return fmt.Errorf("verifyBalanceProofL1Rn: n2 = 1 + nR > 0xFF")
	}

	if len(cmtRs) != int(nR) {
		return fmt.Errorf("verifyBalanceProofL1Rn: The input (nR, cmtRs) does not match")
	}

	if !pp.ValueCommitmentSanityCheck(cmtL) {
		return fmt.Errorf("verifyBalanceProofL1Rn: the input cmtL *ValueCommitment is not well-form")
	}

	for j := 0; j < int(nR); j++ {
		if !pp.ValueCommitmentSanityCheck(cmtRs[j]) {
			return fmt.Errorf("verifyBalanceProofL1Rn: the input cmtRs[%d] is not well-form", j)
		}
	}

	if !pp.BalanceProofL1RnSanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofL1Rn: the input balanceProof *BalanceProofLmRn is not well-form")
	}

	if balanceProof.nL != 1 || balanceProof.nR != nR || balanceProof.vRPub != vRPub {
		return fmt.Errorf("verifyBalanceProofL1Rn: balanceProof.nL (%d) != 1 || balanceProof.nR (%d) != nR (%d) || balanceProof.vRPubv (%v) != vRPub (%v)", balanceProof.nL, balanceProof.nR, nR, balanceProof.vRPub, vRPub)
	}
	//	sanity-checks 	end

	betaF := (pp.paramN - 1) * int(nR) //	for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * (int(nR) - 1)
	}

	boundF := pp.paramEtaF - int64(betaF)
	infNorm := int64(0)
	for i := 0; i < pp.paramDC; i++ {
		infNorm = balanceProof.u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}

		if infNorm > boundF {
			return fmt.Errorf("verifyBalanceProofL1Rn: balanceProof.u_p[%d] (%v) is not in the expected range", i, balanceProof.u_p[i])
		}
	}

	seedMsg, err := pp.collectBytesForBalanceProofL1RnChallenge(msg, nR, cmtL, cmtRs, vRPub, balanceProof.b_hat, balanceProof.c_hats)
	if err != nil {
		return err
	}
	seed_binM, err := Hash(seedMsg)
	if err != nil {
		return err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, pp.paramDC)
	if err != nil {
		return err
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
	err = pp.rpulpVerifyMLP(msg, cmts, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeL1Rn, binM, 1, nR, 3, u_hats, balanceProof.rpulpproof)
	if err != nil {
		return err
	}

	return nil
}

// genBalanceProofLmRn generates BalanceProofLmRn, for the cases
// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// todo: multi-round review
// refactored and reviewed by Alice, 2024.07.04
// todo: review by 2024.07
func (pp *PublicParameter) genBalanceProofLmRn(msg []byte, nL uint8, nR uint8, cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64,
	cmtrLs []*PolyCNTTVec, vLs []uint64, cmtrRs []*PolyCNTTVec, vRs []uint64) (*BalanceProofLmRnGeneral, error) {

	//	sanity-checks	begin
	if len(msg) == 0 {
		return nil, fmt.Errorf("genBalanceProofLmRn: The input msg []byte is empty/nil")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vRPub > V {
		return nil, fmt.Errorf("genBalanceProofLmRn: the input vRPub uint64 (%v) exceeds the allowed maximum value (%v)", vRPub, V)
	}

	if nL > pp.paramI {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofLmRn: the input nL uint8 (%d) exceeds the allowed maximum value (%d)", nL, pp.paramI)
	}
	if nL < 2 {
		return nil, fmt.Errorf("genBalanceProofLmRn: the input nL uint8 (%d) is smaller than 2", nL)
	}

	if nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return nil, fmt.Errorf("genBalanceProofLmRn: the input nR uint8 (%d) exceeds the allowed maximum value (%d)", nR, pp.paramJ)
	}

	if nR == 0 {
		return nil, fmt.Errorf("genBalanceProofLmRn: the input nR uint8 is 0")
	}
	if nR == 1 {
		if vRPub == 0 {
			return nil, fmt.Errorf("genBalanceProofLmRn: the input nR is 1 while vRPub = 0")
		} else {
			// do nothing, since this case is
			// (4) LmR1A: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
		}
	} else {
		// do nothing, since this case is
		// (5) LmRn:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
	}

	n := int(nL) + int(nR)
	n2 := n + 4
	if n2 > 0xFF {
		return nil, fmt.Errorf("genBalanceProofLmRn: n2 = nL + nR > 0xFF")
	}

	if len(cmtLs) != int(nL) || len(cmtrLs) != int(nL) || len(vLs) != int(nL) {
		return nil, fmt.Errorf("genBalanceProofLmRn: The input (nL, cmtLs, cmtrLs, vLs) does not match")
	}

	if len(cmtRs) != int(nR) || len(cmtrRs) != int(nR) || len(vRs) != int(nR) {
		return nil, fmt.Errorf("genBalanceProofLmRn: The input (nR, cmtRs, cmtrRs, vRs) does not match")
	}

	msg_hats := make([][]int64, n2)
	c_hats := make([]*PolyCNTT, n2)

	cmts := make([]*ValueCommitment, n)
	cmtrs := make([]*PolyCNTTVec, n)

	//	Note that the proof is for vLs[0] + ... + vLs[nL-1] = vRs[0] + ... + vRs[nR-1] + vRPub.
	//  This is proved by vLs[0] + ... + vLs[nL-1] = vSum = vRs[0] + ... + vRs[nR-1] + vRPub.

	vSum := uint64(0)

	//	msg_hats[0], ..., msg_hats[nL-1]
	//	vLs[0], ..., vLs[nL-1]
	for i := 0; i < int(nL); i++ {
		if vLs[i] > V {
			return nil, fmt.Errorf("genBalanceProofLmRn: The input vLs[%d] (%v) exceeds the allowed maximum value (%v)", i, vLs[i], V)
		}

		cmts[i] = cmtLs[i]
		cmtrs[i] = cmtrLs[i]
		msg_hats[i] = pp.intToBinary(vLs[i])

		vSum += vLs[i] //	Note that there will be no overflow at this point.

		if vSum > V {
			return nil, fmt.Errorf("genBalanceProofLmRn: The sum of the first %d vLs[] (%v) exceeds the allowed maximum value (%v)", i, vSum, V)
		}

		miNTT, err := pp.NewPolyCNTTFromCoeffs(msg_hats[i])
		if err != nil {
			return nil, err
		}
		if !pp.ValueCommitmentOpen(cmtLs[i], miNTT, cmtrLs[i], 0) {
			return nil, fmt.Errorf("genBalanceProofLmRn: The input (cmtLs, cmtrLs, vLs)[%d] does not match", i)
		}

	}

	vRSum := vRPub // for sanity check
	//	msg_hats[nL], ..., msg_hats[nL+nR-1]
	//	vRs[0], ..., vRs[nR-1]
	for j := 0; j < int(nR); j++ {
		if vRs[j] > V {
			return nil, fmt.Errorf("genBalanceProofLmRn: The input vRs[%d] (%v) exceeds the allowed maximum value (%v)", j, vRs[j], V)
		}

		cmts[int(nL)+j] = cmtRs[j]
		cmtrs[int(nL)+j] = cmtrRs[j]
		msg_hats[int(nL)+j] = pp.intToBinary(vRs[j])

		vRSum += vRs[j] //	Note that there will be no overflow at this point.

		if vRSum > V {
			return nil, fmt.Errorf("genBalanceProofLmRn: The sum of the first %d vRs[] (%v) exceeds the allowed maximum value (%v)", j, vRSum, V)
		}

		mjNTT, err := pp.NewPolyCNTTFromCoeffs(msg_hats[int(nL)+j])
		if err != nil {
			return nil, err
		}
		if !pp.ValueCommitmentOpen(cmtRs[j], mjNTT, cmtrRs[j], 0) {
			return nil, fmt.Errorf("genBalanceProofLmRn: The input (cmtRs, cmtrRs, vRs)[%d] does not match", j)
		}
	}

	if vRSum != vSum {
		return nil, fmt.Errorf("genBalanceProofLmRn: The sum of vLs and the sum of (vRs and vRPub) are not equal")
	}

	//	sanity-checks	end

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
	for j := 0; j < int(nR); j++ {
		tmp = tmp + msg_hats[int(nL)+j][0]
	}
	fR[0] = (tmp + u[0]) >> 1

	// fR[1], ..., fR[d-2], fR[d-1]
	for t := 1; t < pp.paramDC; t++ {
		tmp = int64(0)
		for j := 0; j < int(nR); j++ {
			tmp = tmp + msg_hats[int(nL)+j][t]
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
	betaF := (pp.paramN - 1) * (int(nL) - 1 + int(nR)) // for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * (int(nL) - 1 + int(nR) - 1)
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

	return &BalanceProofLmRnGeneral{
		balanceProofCase: BalanceProofCaseLmRn,
		nL:               nL,
		nR:               nR,
		vRPub:            vRPub,
		// bpf
		b_hat:      b_hat,
		c_hats:     c_hats,
		u_p:        u_p,
		rpulpproof: rprlppi,
	}, nil

}

// verifyBalanceProofLmRn verifies BalanceProofLmRn.
// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// refactored and reviewed by Alice, 2024.07.04
// todo: review by 2024.07
// todo: multi-round review
func (pp *PublicParameter) verifyBalanceProofLmRn(msg []byte, nL uint8, nR uint8, cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, balanceProof *BalanceProofLmRnGeneral) error {

	//	sanity checks	begin
	//	sanity-checks	begin
	if len(msg) == 0 {
		return fmt.Errorf("verifyBalanceProofLmRn: The input msg []byte is empty/nil")
	}

	V := (uint64(1) << pp.paramN) - 1
	if vRPub > V {
		return fmt.Errorf("verifyBalanceProofLmRn: the input vRPub uint64 (%v) exceeds the allowed maximum value (%v)", vRPub, V)
	}

	if nL > pp.paramI {
		// Note that pp.paramI == pp.paramJ
		return fmt.Errorf("verifyBalanceProofLmRn: the input nL uint8 (%d) exceeds the allowed maximum value (%d)", nL, pp.paramI)
	}
	if nL < 2 {
		return fmt.Errorf("verifyBalanceProofLmRn: the input nL uint8 (%d) is smaller than 2", nL)
	}

	if nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return fmt.Errorf("verifyBalanceProofLmRn: the input nR uint8 (%d) exceeds the allowed maximum value (%d)", nR, pp.paramJ)
	}

	if nR == 0 {
		return fmt.Errorf("verifyBalanceProofLmRn: the input nR uint8 is 0")
	}
	if nR == 1 {
		if vRPub == 0 {
			return fmt.Errorf("verifyBalanceProofLmRn: the input nR is 1 while vRPub = 0")
		} else {
			// do nothing, since this case is
			// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
		}
	} else {
		// do nothing, since this case is
		// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
	}

	n := int(nL) + int(nR)
	n2 := n + 4
	if n2 > 0xFF {
		return fmt.Errorf("verifyBalanceProofLmRn: n2 = nL + nR > 0xFF")
	}

	if len(cmtLs) != int(nL) {
		return fmt.Errorf("verifyBalanceProofLmRn: The input (cmtLs, nL) does not match")
	}

	if len(cmtRs) != int(nR) {
		return fmt.Errorf("verifyBalanceProofLmRn: The input (cmtRs, nR) does not match")
	}

	for i := 0; i < int(nL); i++ {
		if !pp.ValueCommitmentSanityCheck(cmtLs[i]) {
			return fmt.Errorf("verifyBalanceProofLmRn: The input cmtLs[%d] is not well-form", i)
		}
	}

	for i := 0; i < int(nR); i++ {
		if !pp.ValueCommitmentSanityCheck(cmtRs[i]) {
			return fmt.Errorf("verifyBalanceProofLmRn: The input cmtRs[%d] is not well-form", i)
		}
	}

	if !pp.BalanceProofLmRnSanityCheck(balanceProof) {
		return fmt.Errorf("verifyBalanceProofLmRn: The input balanceProof *BalanceProofLmRn is not well-form")
	}

	if balanceProof.nL != nL || balanceProof.nR != nR || balanceProof.vRPub != vRPub {
		return fmt.Errorf("verifyBalanceProofLmRn: balanceProof.nL (%d) != nL (%d) || balanceProof.nR (%d) != nR (%d) || balanceProof.vRPub (%v) != vRPub (%v)",
			balanceProof.nL, nL, balanceProof.nR, nR, balanceProof.vRPub, vRPub)
	}
	//	sanity checks	end

	betaF := (pp.paramN - 1) * (int(nL) - 1 + int(nR)) // for the case of vRPub > 0
	if vRPub == 0 {
		betaF = (pp.paramN - 1) * (int(nL) - 1 + int(nR) - 1)
	}
	boundF := pp.paramEtaF - int64(betaF)
	infNorm := int64(0)
	for i := 0; i < pp.paramDC; i++ {
		infNorm = balanceProof.u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}

		if infNorm > boundF {
			return fmt.Errorf("verifyBalanceProofLmRn: balanceProof.u_p[%d] (%v) is not in the expected range", i, balanceProof.u_p[i])
		}
	}

	seedMsg, err := pp.collectBytesForBalanceProofLmRnChallenge(msg, nL, nR, cmtLs, cmtRs, vRPub, balanceProof.b_hat, balanceProof.c_hats)
	if err != nil {
		return err
	}
	seed_binM, err := Hash(seedMsg)
	if err != nil {
		return err
	}
	binM, err := expandBinaryMatrix(seed_binM, pp.paramDC, 2*pp.paramDC)
	if err != nil {
		return err
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

	n1 := n + 1
	err = pp.rpulpVerifyMLP(msg, cmts, uint8(n), balanceProof.b_hat, balanceProof.c_hats, uint8(n2), uint8(n1), RpUlpTypeLmRn, binM, nL, nR, 5, u_hats, balanceProof.rpulpproof)
	if err != nil {
		return err
	}

	return nil
}

// serializeBalanceProof serialize BalanceProof into []byte.
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
// todo: review by 2024.07
func (pp *PublicParameter) serializeBalanceProof(balanceProof BalanceProof) ([]byte, error) {
	if balanceProof == nil {
		return nil, fmt.Errorf("serializeBalanceProof: the input BalanceProof is nil")
	}

	switch bpfInst := balanceProof.(type) {
	case *BalanceProofL0R0:
		return pp.serializeBalanceProofL0R0(bpfInst)
	case *BalanceProofL0R1:
		return pp.serializeBalanceProofL0R1(bpfInst)
	case *BalanceProofL1R1:
		return pp.serializeBalanceProofL1R1(bpfInst)
	case *BalanceProofLmRnGeneral:
		return pp.serializeBalanceProofLmRnGeneral(bpfInst)
	default:
		return nil, fmt.Errorf("serializeBalanceProof: the input BalanceProof is not BalanceProofL0R0, BalanceProofL0R1, BalanceProofL1R1, or BalanceProofLmRnGeneral")
	}
}

// deserializeBalanceProof deserialize []byte to BalanceProof.
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) deserializeBalanceProof(serializedBpf []byte) (BalanceProof, error) {
	if len(serializedBpf) == 0 {
		return nil, fmt.Errorf("deserializeBalanceProof: the input serializedBpf is empty")
	}

	r := bytes.NewReader(serializedBpf)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	switch BalanceProofCase(balanceProofCase) {
	case BalanceProofCaseL0R0:
		return pp.deserializeBalanceProofL0R0(serializedBpf)
	case BalanceProofCaseL0R1:
		return pp.deserializeBalanceProofL0R1(serializedBpf)
	case BalanceProofCaseL0Rn:
		return pp.deserializeBalanceProofLmRnGeneral(serializedBpf)
	case BalanceProofCaseL1R1:
		return pp.deserializeBalanceProofL1R1(serializedBpf)
	case BalanceProofCaseL1Rn:
		return pp.deserializeBalanceProofLmRnGeneral(serializedBpf)
	case BalanceProofCaseLmRn:
		return pp.deserializeBalanceProofLmRnGeneral(serializedBpf)
	default:
		return nil, fmt.Errorf("deserializeBalanceProof: the extracted balanceProofCase (%d) is not suppoted", balanceProofCase)
	}
}

// balanceProofL0R0SerializeSize returns the serialize size for balanceProofL0R0.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) balanceProofL0R0SerializeSize() int {
	n := 1 // balanceProofCase BalanceProofCase
	return n
}

// serializeBalanceProofL0R0 serialize the input BalanceProofL0R0 to []byte.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) serializeBalanceProofL0R0(bpf *BalanceProofL0R0) ([]byte, error) {

	if !pp.BalanceProofL0R0SanityCheck(bpf) {
		return nil, fmt.Errorf("serializeBalanceProofL0R0: the input bpf *BalanceProofL0R0 is not well-form")
	}

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
// reviewed by Alice, 2024.07.05
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

// balanceProofL0R1SerializeSize returns the serialized size for BalanceProofL0R1.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) balanceProofL0R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		HashOutputBytesLen + // chseed           []byte
		+pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // zs        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofL0R1 serialize the input BalanceProofL0R1 to []byte.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) serializeBalanceProofL0R1(bpf *BalanceProofL0R1) ([]byte, error) {

	if !pp.BalanceProofL0R1SanityCheck(bpf) {
		return nil, fmt.Errorf("serializeBalanceProofL0R1: the input bpf *BalanceProofL0R1 is not well-form")
	}

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
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) deserializeBalanceProofL0R1(serializedBpfL0R1 []byte) (*BalanceProofL0R1, error) {

	r := bytes.NewReader(serializedBpfL0R1)

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

// balanceProofL1R1SerializeSize returns the serialized size for BalanceProofL1R1.
// reviewed on 2023.12.07
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) balanceProofL1R1SerializeSize() int {
	n := 1 + // balanceProofCase BalanceProofCase
		pp.PolyCNTTSerializeSize() + //  psi              *PolyCNTT
		HashOutputBytesLen + // chseed           []byte
		+2*pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) // z1s, z2s        []*PolyCVec : dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
	return n
}

// serializeBalanceProofLR1 serialize the input BalanceProofL1R1 to []byte.
// reviewed on 2023.12.07
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) serializeBalanceProofL1R1(bpf *BalanceProofL1R1) ([]byte, error) {

	if !pp.BalanceProofL1R1SanityCheck(bpf) {
		return nil, fmt.Errorf("serializeBalanceProofL1R1: the input bpf *BalanceProofL1R1 is not well-form")
	}

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
// reviewed by Alice, 2024.07.05
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
	z1s := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		z1s[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	//	z2s               []*PolyCVec
	//	fixed-length paramK
	z2s := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		z2s[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
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

// balanceProofLmRnGeneralSerializeSizeByCommNum returns the serialize size for BalanceProofLmRnGeneral,
// according to the left-side commitment number nL and the right-side commitment number nR.
// Note that BalanceProofLmRnGeneral covers the following five cases, where the concrete type depends on (nL, nR), which also decides the value of n2.
// (1) L0Rn  [BalanceProofCaseL0Rn]:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0
// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
// The leftCommNum and rightCommNum are also serialized, since the size can be deterministically computed from these two values.
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) balanceProofLmRnGeneralSerializeSizeByCommNum(nL uint8, nR uint8) (int, error) {

	length := 1 + // balanceProofCase BalanceProofCase
		1 + // nL      uint8
		1 + // nR     uint8
		8 + // vRPub	uint64
		pp.PolyCNTTVecSerializeSizeByVecLen(pp.paramKC) // b_hat            *PolyCNTTVec, with length pp.paramKC

	n := int(nL) + int(nR) // the number of commitments to call rpulpProveMLP
	n2 := n                //	the number of commitments for c_hats
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

	if n2 > 0xFF {
		//	when calling rpulpProve, n2 will be converted into uint8.
		//	we shall always guarantee this point.
		return 0, fmt.Errorf("balanceProofLmRnSerializeSizeByCommNum: n2 > 0xFF")
	}

	length = length +
		VarIntSerializeSize(uint64(n2)) + n2*pp.PolyCNTTSerializeSize() + // c_hats           []*PolyCNTT, length n2
		pp.CarryVectorRProofSerializeSize() //	u_p              []int64	, dimension paramDc, bounded \eta_f

	length = length + pp.rpulpProofMLPSerializeSizeByCommNum(nL, nR) //  rpulpproof       *RpulpProofMLP

	return length, nil
}

// serializeBalanceProofLmRnGeneral serialize the input BalanceProofLmRnGeneral to []byte.
// Note that BalanceProofLmRn (general) covers the following five cases, where the concrete type depends on (nL, nR), which also decides the value of n2.
// (1) L0Rn  [BalanceProofCaseL0Rn]:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0
// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
// reviewed on 2023.12.07
// reviewed on 2023.12.20
// refactored and reviewed by Alice, 2024.07.05
func (pp *PublicParameter) serializeBalanceProofLmRnGeneral(bpf *BalanceProofLmRnGeneral) ([]byte, error) {

	if bpf == nil {
		return nil, fmt.Errorf("serializeBalanceProofLmRnGeneral: the input bpf *BalanceProofLmRn is nil")
	}

	switch bpf.balanceProofCase {
	case BalanceProofCaseL0Rn:
		if !pp.BalanceProofL0RnSanityCheck(bpf) {
			return nil, fmt.Errorf("serializeBalanceProofLmRn: the input bpf *BalanceProofLmRn with BalanceProofCaseL0Rn is not well-form")
		}
	case BalanceProofCaseL1Rn:
		if !pp.BalanceProofL1RnSanityCheck(bpf) {
			return nil, fmt.Errorf("serializeBalanceProofLmRn: the input bpf *BalanceProofLmRn with BalanceProofCaseL1Rn is not well-form")
		}
	case BalanceProofCaseLmRn:
		if !pp.BalanceProofLmRnSanityCheck(bpf) {
			return nil, fmt.Errorf("serializeBalanceProofLmRn: the input bpf *BalanceProofLmRn with BalanceProofCaseLmRn is not well-form")
		}
	default:
		return nil, fmt.Errorf("serializeBalanceProofLmRnGeneral: the input bpf *BalanceProofLmRn has a balanceProofCase not in (BalanceProofCaseL0Rn, BalanceProofCaseL1Rn, BalanceProofCaseLmRn)")
	}

	length, err := pp.balanceProofLmRnGeneralSerializeSizeByCommNum(bpf.nL, bpf.nR)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, length))

	//	balanceProofCase BalanceProofCase
	err = w.WriteByte(byte(bpf.balanceProofCase))
	if err != nil {
		return nil, err
	}

	//	nL      uint8
	err = w.WriteByte(bpf.nL)
	if err != nil {
		return nil, err
	}

	//	nR      uint8
	err = w.WriteByte(bpf.nR)
	if err != nil {
		return nil, err
	}

	//	vRPub
	err = binarySerializer.PutUint64(w, binary.LittleEndian, bpf.vRPub)
	if err != nil {
		return nil, err
	}

	// b_hat            *PolyCNTTVec
	err = pp.writePolyCNTTVec(w, bpf.b_hat)
	if err != nil {
		return nil, err
	}

	//	c_hats           []*PolyCNTT
	//n := int(bpf.nL) + int(bpf.nR) // the number of commitments to call rpulpProveMLP
	//n2 := n                        //	the number of commitments for c_hats
	//if bpf.nL == 0 {
	//	//	A_{L0R2}
	//	n2 = n + 2 // f_R, e
	//} else if bpf.nL == 1 {
	//	// A_{L1R2}
	//	n2 = n + 2 // f_R, e
	//} else {
	//	// nL >= 2
	//	// A_{L2R2}
	//	n2 = n + 4 // m_{sum}, f_L, f_R, e
	//}
	//if n2 > 0xFF {
	//	//	when calling rpulpProve, n2 will be converted into uint8.
	//	//	we shall always guarantee this point.
	//	return nil, fmt.Errorf("serializeBalanceProofLmRnGeneral: n2 = nL + nR  > 0xFF")
	//}

	n2 := len(bpf.c_hats) //	Note that previous sanity checks has guaranteed the well-form of n2.
	err = WriteVarInt(w, uint64(n2))
	if err != nil {
		return nil, err
	}
	for i := 0; i < n2; i++ {
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
	serializedRpulpProof, err := pp.serializeRpulpProofMLP(bpf.rpulpproof)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(serializedRpulpProof)
	if err != nil {
		return nil, err
	}
	//	an assert, can be removed after test
	serializedRpulpProofSize := pp.rpulpProofMLPSerializeSizeByCommNum(bpf.nL, bpf.nR)
	if len(serializedRpulpProof) != serializedRpulpProofSize {
		//	assert
		return nil, fmt.Errorf("serializeBalanceProofLmRn: this shoudl not happen, where the size of serializedRpulpProof is not the same as expected")
	}

	return w.Bytes(), nil
}

// deserializeBalanceProofLmRnGeneral deserialize the input []byte to a BalanceProofLmRn (general).
// Note that BalanceProofLmRn (general) covers the following five cases, where the concrete type depends on (nL, nR), which also decides the value of n2.
// (1) L0Rn  [BalanceProofCaseL0Rn]:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0
// (2) L1R1A [BalanceProofCaseL1Rn]: cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// (4) LmR1A [BalanceProofCaseLmRn]: cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
// reviewed on 2023.12.07
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// refactored and reviewed by Alice, 2024.07.05
func (pp *PublicParameter) deserializeBalanceProofLmRnGeneral(serializedBpfLmRn []byte) (*BalanceProofLmRnGeneral, error) {
	r := bytes.NewReader(serializedBpfLmRn)

	// balanceProofCase BalanceProofCase
	balanceProofCase, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	if BalanceProofCase(balanceProofCase) != BalanceProofCaseL0Rn &&
		BalanceProofCase(balanceProofCase) != BalanceProofCaseL1Rn &&
		BalanceProofCase(balanceProofCase) != BalanceProofCaseLmRn {
		return nil, fmt.Errorf("deserializeBalanceProofLmRnGeneral: the deserialized balanceProofCase is not BalanceProofCaseL0Rn, BalanceProofCaseL1Rn, or BalanceProofCaseLmRn")
	}

	//	nL      uint8
	nL, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	nR      uint8
	nR, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	//	vRPub
	vRPub, err := binarySerializer.Uint64(r, binary.LittleEndian)
	if err != nil {
		return nil, err
	}

	// b_hat            *PolyCNTTVec
	b_hat, err := pp.readPolyCNTTVec(r)
	if err != nil {
		return nil, err
	}

	// c_hats           []*PolyCNTT
	n2Read, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	n := int(nL) + int(nR) // the number of commitments to call rpulpProveMLP
	n2 := n                //	the number of commitments for c_hats
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
	if n2 > 0xFF {
		//	when calling rpulpProve, n2 will be converted into uint8.
		//	we shall always guarantee this point.
		return nil, fmt.Errorf("deserializeBalanceProofLmRnGeneral: n2 from (nL, nR) (%d) > 0xFF", n2)
	}

	if n2Read != uint64(n2) {
		return nil, fmt.Errorf("deserializeBalanceProofLmRnGeneral: the decoded n2 (%d) does not mathc the decoded (nL, nR) (%d, %d)", n2Read, int(nL), int(nR))
	}

	c_hats := make([]*PolyCNTT, n2)
	for i := 0; i < n2; i++ {
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

	return &BalanceProofLmRnGeneral{
		balanceProofCase: BalanceProofCase(balanceProofCase),
		nL:               nL,
		nR:               nR,
		vRPub:            vRPub,
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
// refactored and reviewed by Alice, 2024.07.02
func (pp *PublicParameter) collectBytesForBalanceProofL0R1Challenge(msg []byte, vL uint64, cmt *ValueCommitment, ws []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + // crs
		len(msg) + 8 + pp.ValueCommitmentSerializeSize() +
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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

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
// refactored and reviewed by Alice, 2024.07.03
// todo: review by 2024.07
func (pp *PublicParameter) collectBytesForBalanceProofL0RnChallenge(msg []byte, nR uint8, vL uint64, cmts []*ValueCommitment, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + // crs
		len(msg) + 1 + 8 + len(cmts)*pp.ValueCommitmentSerializeSize() +
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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

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
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.04
func (pp *PublicParameter) collectBytesForBalanceProofL1R1Challenge1(msg []byte, cmt1 *ValueCommitment, cmt2 *ValueCommitment, w1s []*PolyCNTTVec, w2s []*PolyCNTTVec, deltas []*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + //	crs
		len(msg) + //	msg []byte
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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

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
// reviewed on 2023.12.18
// reviewed by Alice, 2024.07.04
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
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.04
func (pp *PublicParameter) collectBytesForBalanceProofL1R1Challenge2(preMsg []byte,
	psi *PolyCNTT, psip *PolyCNTT) []byte {

	length := len(pp.paramParameterSeedString) + // crs
		len(preMsg) + 2*pp.paramDC*8

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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

	//	preMsg []byte
	rst = append(rst, preMsg...)

	// psi
	appendPolyNTTToBytes(psi)

	// psip
	appendPolyNTTToBytes(psip)

	return rst
}

// collectBytesForBalanceProofL1RnChallenge collects pre-message bytes for the challenge in genBalanceProofL1Rn.
// reviewed on 2023.12.18
// refactored and reviewed by Alice, 2024.07.04
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofL1RnChallenge(msg []byte, nR uint8, cmtL *ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + // crs
		len(msg) + 1 + (1+int(nR))*pp.ValueCommitmentSerializeSize() + 8 +
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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

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
// reviewed on 2023.12.18
// reviewed on 2023.12.20
// refactored and reviewed by Alice, 2024.07.05
// todo: multi-round review
func (pp *PublicParameter) collectBytesForBalanceProofLmRnChallenge(msg []byte, nL uint8, nR uint8,
	cmtLs []*ValueCommitment, cmtRs []*ValueCommitment, vRPub uint64, b_hat *PolyCNTTVec, c_hats []*PolyCNTT) ([]byte, error) {

	length := len(pp.paramParameterSeedString) + // crs
		len(msg) + 2 +
		(int(nL)+int(nR))*pp.ValueCommitmentSerializeSize() + 8 +
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

	//	crs
	rst = append(rst, pp.paramParameterSeedString...)

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

// CarryVectorRProofSerializeSize
// For carry vector f, u_p = B*f + e servers as its range proof, where u_p's infinite normal should be smaller than q_c/16.
// e is sampled from [-eta_f, eta_f].
// B*f is bounded by beta_f which has different value for different cases.
// A valid proof for u_p should have infinite normal in [-(eta_f - beta_f), (eta_f - beta_f)].
// Note q_c = 9007199254746113 = 2^{53} + 2^{12} + 2^{10} + 2^{0} is a 54-bit number, and 2^{49}-1 < q_c/16.
// Any eta_f smaller than 2^{49}-1 will be fine.
// We set eta_f = 2^{23}-1.
// Each coefficient of u_p, say in [-(eta_f - beta_f), (eta_f - beta_f)], can be encoded by 3 bytes.
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) CarryVectorRProofSerializeSize() int {
	return pp.paramDC * 3
}

// writeCarryVectorRProof
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) writeCarryVectorRProof(w io.Writer, u_p []int64) error {
	if len(u_p) != pp.paramDC {
		return errors.New("writeCarryVectorRProof: the input carry vector has an incorrect size")
	}

	var coeff int64
	tmp := make([]byte, 3)
	for i := 0; i < pp.paramDC; i++ {
		coeff = u_p[i]
		tmp[0] = byte(coeff >> 0)
		tmp[1] = byte(coeff >> 8)
		tmp[2] = byte(coeff >> 16)
		_, err := w.Write(tmp)
		if err != nil {
			return err
		}
	}
	return nil
}

// readCarryVectorRProof
// moved from serialization.go on 2024.06.21
// reviewed by Alice, 2024.06.22
// reviewed by Alice, 2024.07.05
func (pp *PublicParameter) readCarryVectorRProof(r io.Reader) ([]int64, error) {
	u_p := make([]int64, pp.paramDC)

	var coeff int64
	tmp := make([]byte, 3)
	for i := 0; i < pp.paramDC; i++ {
		_, err := r.Read(tmp)
		if err != nil {
			return nil, err
		}
		coeff = int64(tmp[0]) << 0
		coeff |= int64(tmp[1]) << 8
		coeff |= int64(tmp[2]) << 16
		if tmp[2]>>7 == 1 {
			//	23-bit for absolute
			coeff = int64(uint64(coeff) | 0xFFFFFFFFFF000000)
		}
		u_p[i] = coeff
	}
	return u_p, nil
}

//	helper functions	end

//	sanity-check functions	begin

// BalanceProofL0R0SanityCheck checks whether the input balanceProof *BalanceProofL0R0 is well-form:
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct.
// added by Alice, 2024.07.03
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofL0R0SanityCheck(balanceProof *BalanceProofL0R0) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseL0R0 {
		return false
	}

	return true
}

// BalanceProofL0R1SanityCheck checks whether the input balanceProof *BalanceProofL0R1 is well-form:
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct;
// (3) balanceProof.zs() is well-form, including the normal.
// added by Alice, 2024.07.03
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofL0R1SanityCheck(balanceProof *BalanceProofL0R1) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseL0R1 {
		return false
	}

	if len(balanceProof.chseed) != HashOutputBytesLen {
		return false
	}

	if len(balanceProof.zs) != pp.paramK {
		return false
	}

	zBoundC := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
		if balanceProof.zs[t] == nil {
			return false
		}

		if len(balanceProof.zs[t].polyCs) != pp.paramLC {
			return false
		}

		for i := 0; i < pp.paramLC; i++ {
			if !pp.PolyCSanityCheck(balanceProof.zs[t].polyCs[i]) {
				return false
			}
			if balanceProof.zs[t].polyCs[i].infNorm() > zBoundC {
				return false
			}
		}

	}

	return true
}

// BalanceProofLmRnGeneralCommonSanityCheck conduct the common sanity checks of BalanceProofLmRnGeneral, and should/will be called as a subroutine of
// BalanceProofL0RnSanityCheck, BalanceProofL1RnSanityCheck (for the following (2) L1R1A and (3) L1Rn), BalanceProofLmRnSanityCheck for the following ((4) LmR1A and (5) LmRn) .
// Note that the five cases of BalanceProof share the same structure of BalanceProofLmRn, and the concrete case depends on (nL, nR), which also decides the value of n2.
// (1) L0Rn  [BalanceProofCaseL0Rn]:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0
// (2) L1R1A [BalanceProofCaseL1Rn]:  cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0
// (4) LmR1A [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0
func (pp *PublicParameter) BalanceProofLmRnGeneralCommonSanityCheck(balanceProof *BalanceProofLmRnGeneral) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.nL > pp.paramI || balanceProof.nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ.
		return false
	}

	n := int(balanceProof.nL) + int(balanceProof.nR)
	n2 := n
	if balanceProof.nL == 0 {
		//	A_{L0R2}
		n2 = n + 2 // f_R, e
	} else if balanceProof.nL == 1 {
		// A_{L1R2}
		n2 = n + 2 // f_R, e
	} else {
		// nL >= 2
		// A_{L2R2}
		n2 = n + 4 // m_{sum}, f_L, f_R, e
	}

	if n2 > 0xFF {
		//	when calling rpulpProve, n2 will be converted into uint8.
		//	we shall always guarantee this point.
		return false
	}

	if balanceProof.b_hat == nil {
		return false
	}
	if len(balanceProof.b_hat.polyCNTTs) != pp.paramK {
		return false
	}
	for i := 0; i < pp.paramK; i++ {
		if !pp.PolyCNTTSanityCheck(balanceProof.b_hat.polyCNTTs[i]) {
			return false
		}
	}

	if len(balanceProof.c_hats) != n2 {
		return false
	}
	for i := 0; i < n2; i++ {
		if !pp.PolyCNTTSanityCheck(balanceProof.c_hats[i]) {
			return false
		}
	}

	if len(balanceProof.u_p) != pp.paramDC {
		return false
	}
	for i := 0; i < pp.paramDC; i++ {
		infNorm := balanceProof.u_p[i]
		if infNorm < 0 {
			infNorm = -infNorm
		}
		if infNorm > pp.paramEtaF {
			// Here only the coarse check is conducted, while it is the responsibility of the caller to check pp.paramEtaF - boundF,
			// since boundF depends on concrete cases.
			return false
		}
	}

	if !pp.RpulpProofSanityCheck(balanceProof.rpulpproof) {
		return false
	}

	if balanceProof.rpulpproof.nL != balanceProof.nL ||
		balanceProof.rpulpproof.nR != balanceProof.nR {
		return false
	}
	//	This part is common for BalanceProofLmRn.	end

	return true
}

// BalanceProofL0RnSanityCheck checks whether the input balanceProof *BalanceProofLmRnGeneral is well-form.
// Note that BalanceProofL0Rn is for the case (1) L0Rn  [BalanceProofCaseL0Rn]:  v = cmt_1 + ... + cmt_n, where n >= 2, v >= 0.
// The checks include
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct;
// (3) balanceProof.nL and balanceProof.nR are correct, say, match the BalanceProofCase;
// (4) balanceProof.(b_hat, c_hats, u_p, rpulpproof) is well-from, by calling the BalanceProofLmRnCommonSanityCheck.
// added by Alice, 2024.07.04
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofL0RnSanityCheck(balanceProof *BalanceProofLmRnGeneral) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseL0Rn {
		//	Key feature of L0Rn from BalanceProofLmRnGeneral
		return false
	}

	if balanceProof.nL != 0 {
		//	Key feature of L0Rn from BalanceProofLmRnGeneral: balanceProof.nL = 0
		return false
	}

	if balanceProof.nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return false
	}
	if balanceProof.nR < 2 {
		//	Key feature of L0Rn from BalanceProofLmRnGeneral: balanceProof.nR >= 2
		return false
	}

	if balanceProof.vRPub != 0 {
		//	Key feature of L0Rn from BalanceProofLmRnGeneral: balanceProof.vRPub == 0
		return false
	}

	if !pp.BalanceProofLmRnGeneralCommonSanityCheck(balanceProof) {
		return false
	}

	return true
}

// BalanceProofL1R1SanityCheck checks whether the input balanceProof *BalanceProofL1R1 is well-form:
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct;
// (3) balanceProof.psi is well-form;
// (4) balanceProof.chseed is well-form;
// (5) balanceProof.z1s and balanceProof.z2s are well-form, including the normal.
// added by Alice, 2024.07.03
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofL1R1SanityCheck(balanceProof *BalanceProofL1R1) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseL1R1 {
		return false
	}

	if !pp.PolyCNTTSanityCheck(balanceProof.psi) {
		return false
	}

	if len(balanceProof.chseed) != HashOutputBytesLen {
		return false
	}

	if len(balanceProof.z1s) != pp.paramK || len(balanceProof.z2s) != pp.paramK {
		return false
	}
	zBoundC := pp.paramEtaC - int64(pp.paramBetaC)
	for t := 0; t < pp.paramK; t++ {
		if balanceProof.z1s[t] == nil || balanceProof.z2s[t] == nil {
			return false
		}

		if len(balanceProof.z1s[t].polyCs) != pp.paramLC || len(balanceProof.z2s[t].polyCs) != pp.paramLC {
			return false
		}

		for i := 0; i < pp.paramLC; i++ {
			if !pp.PolyCSanityCheck(balanceProof.z1s[t].polyCs[i]) || !pp.PolyCSanityCheck(balanceProof.z2s[t].polyCs[i]) {
				return false
			}
			if balanceProof.z1s[t].polyCs[i].infNorm() > zBoundC || balanceProof.z2s[t].polyCs[i].infNorm() > zBoundC {
				return false
			}
		}
	}

	return true
}

// BalanceProofL1RnSanityCheck checks whether the input balanceProof *BalanceProofLmRnGeneral is well-form.
// Note that BalanceProofL1Rn is for the cases
// (2) L1R1A [BalanceProofCaseL1Rn]:  cmtL = cmtR + vRPub, where vRPub > 0
// (3) L1Rn  [BalanceProofCaseL1Rn]:  cmtL = cmtR_1 + ... + cmtR_n + vRPub, where n >= 2, vRPub >= 0.
// The checks include
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct;
// (3) balanceProof.nL and balanceProof.nR are correct, say, match the BalanceProofCase;
// (4) balanceProof.(b_hat, c_hats, u_p, rpulpproof) is well-from, by calling the BalanceProofLmRnCommonSanityCheck.
// added by Alice, 2024.07.04
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofL1RnSanityCheck(balanceProof *BalanceProofLmRnGeneral) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseL1Rn {
		//	Key feature of L1Rn from BalanceProofLmRnGeneral
		return false
	}

	if balanceProof.nL != 1 {
		//	Key feature of L1Rn from BalanceProofLmRnGeneral: balanceProof.nL = 1
		return false
	}

	if balanceProof.nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return false
	}

	V := (uint64(1) << pp.paramN) - 1
	if balanceProof.vRPub > V {
		return false
	}

	//	Key feature of L1Rn from BalanceProofLmRnGeneral: (balanceProof.nR >= 2) || (balanceProof.nR == 1 AND balanceProof.vRPub > 0)
	if balanceProof.nR == 0 {
		return false
	}
	if balanceProof.nR == 1 {
		if balanceProof.vRPub == 0 {
			return false
		} else {
			// balanceProof.vRPub > 0
		}
	} else {
		// balanceProof.nR >= 2
	}

	if !pp.BalanceProofLmRnGeneralCommonSanityCheck(balanceProof) {
		return false
	}

	return true
}

// BalanceProofLmRnSanityCheck checks whether the input balanceProof *BalanceProofLmRnGeneral is well-form.
// Note that BalanceProofLmRn here is for the cases
// (4) LmR1A [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR + vRPub, where m >= 2, vRPub > 0
// (5) LmRn  [BalanceProofCaseLmRn]:  cmtL_1 + ... + cmtL_m = cmtR_1 + ... + cmtR_n + vRPub, where m >=2, n >= 2, vRPub >= 0.
// The checks include
// (1) balanceProof is not nil;
// (2) balanceProof.BalanceProofCase() is correct;
// (3) balanceProof.nL and balanceProof.nR are correct, say, match the BalanceProofCase;
// (4) balanceProof.(b_hat, c_hats, u_p, rpulpproof) is well-from, by calling the BalanceProofLmRnCommonSanityCheck.
// added by Alice, 2024.07.05
// todo: review, by 2024.07
func (pp *PublicParameter) BalanceProofLmRnSanityCheck(balanceProof *BalanceProofLmRnGeneral) bool {

	if balanceProof == nil {
		return false
	}

	if balanceProof.BalanceProofCase() != BalanceProofCaseLmRn {
		//	Key feature of LmRn from BalanceProofLmRn
		return false
	}

	if balanceProof.nL > pp.paramI {
		// Note that pp.paramI == pp.paramJ
		return false
	}

	if balanceProof.nL < 2 {
		//	Key feature of LmRn from BalanceProofLmRn: balanceProof.nL >= 2
		return false
	}

	if balanceProof.nR > pp.paramJ {
		// Note that pp.paramI == pp.paramJ
		return false
	}

	V := (uint64(1) << pp.paramN) - 1
	if balanceProof.vRPub > V {
		return false
	}

	//	Key feature of LmRn from BalanceProofLmRnGeneral: (balanceProof.nR >= 2) || (balanceProof.nR == 1 AND balanceProof.vRPub > 0)
	if balanceProof.nR == 0 {
		return false
	}
	if balanceProof.nR == 1 {
		if balanceProof.vRPub == 0 {
			return false
		} else {
			// balanceProof.vRPub > 0
		}
	} else {
		// balanceProof.nR >= 2
	}

	if !pp.BalanceProofLmRnGeneralCommonSanityCheck(balanceProof) {
		return false
	}

	return true
}

//	sanity-check functions	end
