package pqringctx

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

type RpUlpTypeMLP uint8

const (
	RpUlpTypeL0Rn RpUlpTypeMLP = 0 //  A_{L0R2}
	RpUlpTypeL1Rn RpUlpTypeMLP = 1 //	A_{L1R2}
	RpUlpTypeLmRn RpUlpTypeMLP = 2 //	A_{L2R2}
)

// RpulpProofMLP define the range-proof and unstructed-linear-relation-proof.
// All the three cases, say (RpUlpTypeL0Rn, RpUlpTypeL1Rn, and RpUlpTypeLmRn), have the same structures.
// Concrete rpulpProofMLP instances may have different sizes, depending on the number of commitments, say n := nL + nR.
// Here we give explicit nL and nR, rather than n, to keep more fine-grained data, in case the future extension. In addition,
// rpUlpType is actually computed from nL and nR by the caller/creator or rpulpProofMLP instance. To be self-contained, we put (nL, nR) in rpulpProofMLP.
// reviewed on 2023.12.05.
type RpulpProofMLP struct {
	rpUlpType RpUlpTypeMLP
	nL        uint8
	nR        uint8
	// proof
	c_waves []*PolyCNTT //	length n := nL + nR
	c_hat_g *PolyCNTT
	psi     *PolyCNTT
	phi     *PolyCNTT
	chseed  []byte
	//	cmt_zs and zs, as the responses, need to have the infinite normal in a scope, say [-(eta_c-beta_c), (eta_c-beta_c)].
	//	That is why here we use PolyCVec rather than PolyCNTTVec.
	cmt_zs [][]*PolyCVec //	dimension [paramK][n], each is a PolyCVec with vevLen = paramLc, i.e., (S_{eta_c - beta_c})^{L_c}
	zs     []*PolyCVec   //	dimension [paramK], each is a PolyCVec with vevLen = paramLc, i.e, (S_{eta_c - beta_c})^{L_c}
}

// rpulpProveMLP generates rpulpProofMLP for the input cmts, including range proof and unstructured-linear-relation proof.
// reviewed on 2023.12.05.
func (pp *PublicParameter) rpulpProveMLP(message []byte, cmts []*ValueCommitment, cmt_rs []*PolyCNTTVec, n uint8,
	b_hat *PolyCNTTVec, r_hat *PolyCNTTVec, c_hats []*PolyCNTT, msg_hats [][]int64, n2 uint8,
	n1 uint8, rpulpType RpUlpTypeMLP, binMatrixB [][]byte,
	nL uint8, nR uint8, m uint8, u_hats [][]int64) (rpulppi *RpulpProofMLP, err error) {

	// c_waves[i] = <h_i, r_i> + m_i
	c_waves := make([]*PolyCNTT, n)
	for i := uint8(0); i < n; i++ {
		tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], cmt_rs[i], pp.paramLC)
		c_waves[i] = pp.PolyCNTTAdd(tmp, &PolyCNTT{coeffs: msg_hats[i]})
	}

rpUlpProveMLPRestart:
	tmpg, err := pp.samplePloyCWithLowZeros()
	if err != nil {
		return nil, err
	}
	g := pp.NTTPolyC(tmpg)
	// c_hat(n2+1)
	c_hat_g := pp.PolyCNTTAdd(pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], r_hat, pp.paramLC), g)

	cmt_ys := make([][]*PolyCNTTVec, pp.paramK)
	ys := make([]*PolyCNTTVec, pp.paramK)
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_ys[t] = make([]*PolyCNTTVec, n)
		cmt_ws[t] = make([]*PolyCNTTVec, n)
		for i := uint8(0); i < n; i++ {
			// random some element in the {s_etaC}^Lc space
			y_ploy, err := pp.sampleMaskingVecC()
			if err != nil {
				return nil, err
			}
			cmt_ys[t][i] = pp.NTTPolyCVec(y_ploy)
			cmt_ws[t][i] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_ys[t][i], pp.paramKC, pp.paramLC)
		}

		y_ploy, err := pp.sampleMaskingVecC()
		if err != nil {
			return nil, err
		}
		ys[t] = pp.NTTPolyCVec(y_ploy)
		ws[t] = pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, ys[t], pp.paramKC, pp.paramLC)
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)
		for i := uint8(0); i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTVecInnerProduct(pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC), cmt_ys[t][i], pp.paramLC)
			delta_hats[t][i] = pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], pp.PolyCNTTVecSub(ys[t], cmt_ys[t][i], pp.paramLC), pp.paramLC)
		}
	}

	// splicing the data to be processed
	preMsg := pp.collectBytesForRPULP1MLP(message, cmts, n, b_hat, c_hats, n2, n1, rpulpType, binMatrixB, nL, nR, m, u_hats, c_waves, c_hat_g, cmt_ws, delta_waves, delta_hats, ws)
	seed_rand, err := Hash(preMsg) // todo_DONE
	if err != nil {
		return nil, err
	}
	//fmt.Println("prove seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandCombChallengeInRpulp(seed_rand, n1, m)
	if err != nil {
		return nil, err
	}

	//	psi, psi'
	psi := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], r_hat, pp.paramLC)
	psip := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], ys[0], pp.paramLC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()
		// sum(0->n1-1)
		for i := uint8(0); i < n1; i++ {
			// <h_i , y_t>
			tmp := pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], ys[t], pp.paramLC)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				// alpha[i] * (2 * m_i - mu) <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					// (2 * m_i - mu) <h_i , y_t>
					pp.PolyCNTTMul(
						// 2 * m_i - mu
						pp.PolyCNTTSub(
							//  m_i+m_i
							pp.PolyCNTTAdd(
								&PolyCNTT{coeffs: msg_hats[i]},
								&PolyCNTT{coeffs: msg_hats[i]},
							),
							pp.paramMu,
						),
						tmp,
					),
				),
			)
			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				// alpha[i] * <h_i , y_t> * <h_i , y_t>
				pp.PolyCNTTMul(
					alphas[i],
					pp.PolyCNTTMul(tmp, tmp),
				),
			)
		}

		psi = pp.PolyCNTTSub(psi, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp1, t)))
		psip = pp.PolyCNTTAdd(psip, pp.PolyCNTTMul(betas[t], pp.sigmaInvPolyCNTT(tmp2, t)))
	}
	//fmt.Printf("Prove\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p, err := pp.genUlpPolyCNTTsMLP(rpulpType, binMatrixB, nL, nR, gammas)
	if err != nil {
		return nil, err
	}

	//	phi
	phi := pp.NewZeroPolyCNTT()

	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := uint8(0); j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], &PolyCNTT{coeffs: msg_hats[j]}))
			}

			constPoly := pp.NewZeroPolyC()
			//constPoly.coeffs[0] = reduceToQc(intMatrixInnerProductWithReductionQc(u_hats, gammas[t], m, pp.paramDC, pp.paramQC) * int64(pp.paramDCInv))
			inprd.SetInt64(pp.intMatrixInnerProductWithReductionQc(u_hats, gammas[t], int(m), pp.paramDC))
			inprd.Mul(&inprd, &dcInv)
			//constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)
			inprd.Mod(&inprd, bigQc)
			constPoly.coeffs[0] = reduceInt64(inprd.Int64(), pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))
			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phi = pp.PolyCNTTAdd(phi, tmp1)
	}

	phi = pp.PolyCNTTAdd(phi, g)
	//phiinv := pp.NTTInv(phi)
	//fmt.Println(phiinv)
	//fmt.Printf("Prove\n")
	//fmt.Printf("phi = %v\n", phi)
	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := uint8(0); j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, ys[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], ys[xi], pp.paramLC))
	}
	//fmt.Println("phips = ")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Prove")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	fmt.Printf("delta_hats[%d] = %v\n", i, phips[i])
	//}
	//	seed_ch and ch
	preMsgAll := pp.collectBytesForRPULP2MLP(preMsg, psi, psip, phi, phips)
	chseed, err := Hash(preMsgAll)
	if err != nil {
		return nil, err
	}
	ch_ploy, err := pp.expandChallengeC(chseed)
	if err != nil {
		return nil, err
	}
	ch := pp.NTTPolyC(ch_ploy)
	// z = y + sigma^t(c) * r
	cmt_zs_ntt := make([][]*PolyCNTTVec, pp.paramK)
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)
	cmt_zs := make([][]*PolyCVec, pp.paramK)
	zs := make([]*PolyCVec, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		cmt_zs_ntt[t] = make([]*PolyCNTTVec, n)
		cmt_zs[t] = make([]*PolyCVec, n)
		sigma_t_ch := pp.sigmaPowerPolyCNTT(ch, t)
		for i := uint8(0); i < n; i++ {
			cmt_zs_ntt[t][i] = pp.PolyCNTTVecAdd(
				cmt_ys[t][i],
				pp.PolyCNTTVecScaleMul(sigma_t_ch, cmt_rs[i], pp.paramLC),
				pp.paramLC)

			cmt_zs[t][i] = pp.NTTInvPolyCVec(cmt_zs_ntt[t][i])
			if cmt_zs[t][i].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				goto rpUlpProveMLPRestart
			}
		}

		zs_ntt[t] = pp.PolyCNTTVecAdd(ys[t], pp.PolyCNTTVecScaleMul(sigma_t_ch, r_hat, pp.paramLC), pp.paramLC)
		zs[t] = pp.NTTInvPolyCVec(zs_ntt[t])
		if zs[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			goto rpUlpProveMLPRestart
		}
	}

	retrpulppi := &RpulpProofMLP{
		rpUlpType: rpulpType,
		nL:        nL,
		nR:        nR,
		c_waves:   c_waves,
		c_hat_g:   c_hat_g,
		psi:       psi,
		phi:       phi,
		chseed:    chseed,
		cmt_zs:    cmt_zs,
		zs:        zs,
	}

	return retrpulppi, nil
}

// rpulpVerifyMLP verifies rpulpProofMLP for the input cmts, range proof and unstructured-linear-relation proof.
// reviewed on 2023.12.05.
func (pp *PublicParameter) rpulpVerifyMLP(message []byte,
	cmts []*ValueCommitment, n uint8,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 uint8,
	n1 uint8, rpulpType RpUlpTypeMLP, binMatrixB [][]byte, nL uint8, nR uint8, m uint8, u_hats [][]int64,
	rpulppi *RpulpProofMLP) (valid bool) {

	if rpulppi == nil {
		return false
	}

	if rpulppi.rpUlpType != rpulpType || rpulppi.nL != nL || rpulppi.nR != nR {
		return false
	}

	if !(n >= 2 && n <= n1 && n1 <= n2 && int(n) <= pp.paramI+pp.paramJ && int(n2) <= pp.paramI+pp.paramJ+4) {
		return false
	}

	if int(nL) > pp.paramI || int(nR) > pp.paramJ { // Note that pp.paramI == pp.paramJ
		return false
	}

	if n != nL+nR { // nL (resp. nR) is the number of commitments on left (resp. right) side
		return false
	}

	if len(cmts) != int(n) {
		return false
	}

	if b_hat == nil {
		return false
	}

	if len(c_hats) != int(n2) {
		return false
	}

	// check the matrix and u_hats
	if len(binMatrixB) != pp.paramDC {
		return false
	} else {
		for i := 0; i < len(binMatrixB); i++ {
			switch rpulpType {
			case RpUlpTypeL0Rn:
				fallthrough
			case RpUlpTypeL1Rn:
				if len(binMatrixB[i]) != pp.paramDC/8 {
					return false
				}
			case RpUlpTypeLmRn:
				if len(binMatrixB[i]) != 2*pp.paramDC/8 {
					return false
				}
			default:
				return false
			}
		}
	}
	if len(u_hats) != int(m) {
		return false
	} else {
		for i := 0; i < len(u_hats); i++ {
			if len(u_hats[i]) != pp.paramDC {
				return false
			}
		}

	}
	// check the well-formness of the \pi
	//if len(rpulppi.c_waves) != int(n) || len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs) != pp.paramDC || len(rpulppi.zs) != pp.paramK || len(rpulppi.zs[0].polyCs) != pp.paramLC {
	//	return false
	//}

	if len(rpulppi.c_waves) != int(n) {
		return false
	}

	if rpulppi.c_hat_g == nil || rpulppi.psi == nil || rpulppi.phi == nil || rpulppi.chseed == nil {
		return false
	}
	if len(rpulppi.c_hat_g.coeffs) != pp.paramDC || len(rpulppi.psi.coeffs) != pp.paramDC || len(rpulppi.phi.coeffs) != pp.paramDC {
		return false
	}

	if rpulppi.cmt_zs == nil || len(rpulppi.cmt_zs) != pp.paramK || rpulppi.zs == nil || len(rpulppi.zs) != pp.paramK {
		return false
	}

	for t := 0; t < pp.paramK; t++ {
		if rpulppi.cmt_zs[t] == nil || len(rpulppi.cmt_zs[t]) != int(n) {
			return false
		}
	}

	//	(phi_t[0] ... phi_t[k-1] = 0)
	phiPoly := pp.NTTInvPolyC(rpulppi.phi)
	//fmt.Println("phiPoly", phiPoly.coeffs1)
	for t := 0; t < pp.paramK; t++ {
		if phiPoly.coeffs[t] != 0 {
			return false
		}
	}

	// infNorm of z^t_i and z^t
	for t := 0; t < pp.paramK; t++ {
		for i := uint8(0); i < n; i++ {
			if rpulppi.cmt_zs[t][i].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
				return false
			}
		}
		if rpulppi.zs[t].infNorm() > pp.paramEtaC-int64(pp.paramBetaC) {
			return false
		}
	}
	ch_poly, err := pp.expandChallengeC(rpulppi.chseed)
	if err != nil {
		return false
	}
	ch := pp.NTTPolyC(ch_poly)

	sigma_chs := make([]*PolyCNTT, pp.paramK)
	//	w^t_i, w_t
	cmt_ws := make([][]*PolyCNTTVec, pp.paramK)
	ws := make([]*PolyCNTTVec, pp.paramK)

	cmt_zs_ntt := make([][]*PolyCNTTVec, pp.paramK)
	zs_ntt := make([]*PolyCNTTVec, pp.paramK)

	for t := 0; t < pp.paramK; t++ {
		sigma_chs[t] = pp.sigmaPowerPolyCNTT(ch, t)

		cmt_ws[t] = make([]*PolyCNTTVec, n)
		cmt_zs_ntt[t] = make([]*PolyCNTTVec, n)

		for i := uint8(0); i < n; i++ {
			cmt_zs_ntt[t][i] = pp.NTTPolyCVec(rpulppi.cmt_zs[t][i])

			cmt_ws[t][i] = pp.PolyCNTTVecSub(
				pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, cmt_zs_ntt[t][i], pp.paramKC, pp.paramLC),
				pp.PolyCNTTVecScaleMul(sigma_chs[t], cmts[i].b, pp.paramKC),
				pp.paramKC)
		}

		zs_ntt[t] = pp.NTTPolyCVec(rpulppi.zs[t])
		ws[t] = pp.PolyCNTTVecSub(
			pp.PolyCNTTMatrixMulVector(pp.paramMatrixB, zs_ntt[t], pp.paramKC, pp.paramLC),
			pp.PolyCNTTVecScaleMul(sigma_chs[t], b_hat, pp.paramKC),
			pp.paramKC)
	}

	//	\tilde{\delta}^(t)_i, \hat{\delta}^(t)_i,
	delta_waves := make([][]*PolyCNTT, pp.paramK)
	delta_hats := make([][]*PolyCNTT, pp.paramK)
	for t := 0; t < pp.paramK; t++ {
		delta_waves[t] = make([]*PolyCNTT, n)
		delta_hats[t] = make([]*PolyCNTT, n)

		for i := uint8(0); i < n; i++ {
			delta_waves[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.PolyCNTTVecSub(pp.paramMatrixH[i+1], pp.paramMatrixH[0], pp.paramLC),
					cmt_zs_ntt[t][i],
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(rpulppi.c_waves[i], cmts[i].c)),
			)

			delta_hats[t][i] = pp.PolyCNTTSub(
				pp.PolyCNTTVecInnerProduct(
					pp.paramMatrixH[i+1],
					pp.PolyCNTTVecSub(zs_ntt[t], cmt_zs_ntt[t][i], pp.paramLC),
					pp.paramLC),
				pp.PolyCNTTMul(sigma_chs[t], pp.PolyCNTTSub(c_hats[i], rpulppi.c_waves[i])),
			)
		}
	}

	// splicing the data to be processed

	preMsg := pp.collectBytesForRPULP1MLP(message, cmts, n, b_hat, c_hats, n2, n1, rpulpType, binMatrixB, nL, nR, m, u_hats,
		rpulppi.c_waves, rpulppi.c_hat_g, cmt_ws, delta_waves, delta_hats, ws)
	seed_rand, err := Hash(preMsg)
	if err != nil {
		return false
	}
	//fmt.Println("verify seed_rand=", seed_rand)
	alphas, betas, gammas, err := pp.expandCombChallengeInRpulp(seed_rand, n1, m)
	if err != nil {
		return false
	}

	// psi'
	psip := pp.NewZeroPolyCNTT()
	//mu := pp.paramMu
	for t := 0; t < pp.paramK; t++ {

		tmp1 := pp.NewZeroPolyCNTT()
		tmp2 := pp.NewZeroPolyCNTT()

		for i := uint8(0); i < n1; i++ {
			f_t_i := pp.PolyCNTTSub(
				//<h_i,z_t>
				pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[i+1], zs_ntt[t], pp.paramLC),
				// sigma_c_t
				pp.PolyCNTTMul(sigma_chs[t], c_hats[i]),
			)

			tmp := pp.PolyCNTTMul(alphas[i], f_t_i)

			tmp1 = pp.PolyCNTTAdd(
				tmp1,
				pp.PolyCNTTMul(tmp, f_t_i),
			)

			tmp2 = pp.PolyCNTTAdd(
				tmp2,
				tmp,
			)
		}
		tmp2 = pp.PolyCNTTMul(tmp2, pp.paramMu)
		tmp2 = pp.PolyCNTTMul(tmp2, sigma_chs[t])

		tmp1 = pp.PolyCNTTAdd(tmp1, tmp2)
		tmp1 = pp.sigmaInvPolyCNTT(tmp1, t)
		tmp1 = pp.PolyCNTTMul(betas[t], tmp1)

		psip = pp.PolyCNTTAdd(psip, tmp1)
	}

	psip = pp.PolyCNTTSub(psip, pp.PolyCNTTMul(ch, rpulppi.psi))
	psip = pp.PolyCNTTAdd(psip,
		pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+6], zs_ntt[0], pp.paramLC))
	//fmt.Printf("Verify\n")
	//fmt.Printf("psip = %v\n", psip)
	//	p^(t)_j:
	p, err := pp.genUlpPolyCNTTsMLP(rpulpType, binMatrixB, nL, nR, gammas)
	if err != nil {
		return false
	}

	//	phip
	phip := pp.NewZeroPolyCNTT()
	var inprd, dcInv big.Int
	dcInv.SetInt64(pp.paramDCInv)
	bigQc := new(big.Int).SetInt64(pp.paramQC)

	for t := 0; t < pp.paramK; t++ {
		tmp1 := pp.NewZeroPolyCNTT()
		for tau := 0; tau < pp.paramK; tau++ {

			tmp := pp.NewZeroPolyCNTT()
			for j := uint8(0); j < n2; j++ {
				tmp = pp.PolyCNTTAdd(tmp, pp.PolyCNTTMul(p[t][j], c_hats[j]))
			}

			constPoly := pp.NewZeroPolyC()
			inprd.SetInt64(pp.intMatrixInnerProductWithReductionQc(u_hats, gammas[t], int(m), pp.paramDC))
			inprd.Mul(&inprd, &dcInv)
			//constPoly.coeffs[0] = reduceBigInt(&inprd, pp.paramQC)
			inprd.Mod(&inprd, bigQc)
			constPoly.coeffs[0] = reduceInt64(inprd.Int64(), pp.paramQC)

			tmp = pp.PolyCNTTSub(tmp, pp.NTTPolyC(constPoly))

			tmp1 = pp.PolyCNTTAdd(tmp1, pp.sigmaPowerPolyCNTT(tmp, tau))
		}

		xt := pp.NewZeroPolyC()
		xt.coeffs[t] = pp.paramKInv

		tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

		phip = pp.PolyCNTTAdd(phip, tmp1)
	}

	//	phi'^(\xi)
	phips := make([]*PolyCNTT, pp.paramK)
	constterm := pp.PolyCNTTSub(pp.PolyCNTTAdd(phip, rpulppi.c_hat_g), rpulppi.phi)

	for xi := 0; xi < pp.paramK; xi++ {
		phips[xi] = pp.NewZeroPolyCNTT()

		for t := 0; t < pp.paramK; t++ {

			tmp1 := pp.NewZeroPolyCNTT()
			for tau := 0; tau < pp.paramK; tau++ {

				tmp := pp.NewZeroPolyCNTTVec(pp.paramLC)

				for j := uint8(0); j < n2; j++ {
					tmp = pp.PolyCNTTVecAdd(
						tmp,
						pp.PolyCNTTVecScaleMul(p[t][j], pp.paramMatrixH[j+1], pp.paramLC),
						pp.paramLC)
				}

				tmp1 = pp.PolyCNTTAdd(
					tmp1,
					pp.sigmaPowerPolyCNTT(
						pp.PolyCNTTVecInnerProduct(tmp, zs_ntt[(xi-tau+pp.paramK)%pp.paramK], pp.paramLC),
						tau),
				)
			}

			xt := pp.NewZeroPolyC()
			xt.coeffs[t] = pp.paramKInv

			tmp1 = pp.PolyCNTTMul(pp.NTTPolyC(xt), tmp1)

			phips[xi] = pp.PolyCNTTAdd(phips[xi], tmp1)
		}

		phips[xi] = pp.PolyCNTTAdd(
			phips[xi],
			pp.PolyCNTTVecInnerProduct(pp.paramMatrixH[pp.paramI+pp.paramJ+5], zs_ntt[xi], pp.paramLC))

		phips[xi] = pp.PolyCNTTSub(
			phips[xi],
			pp.PolyCNTTMul(sigma_chs[xi], constterm))
	}
	//fmt.Printf("Verify\n")
	//
	//fmt.Printf("phips = \n")
	//for i := 0; i < pp.paramK; i++ {
	//	fmt.Printf("phips[%d] = %v \n", i, phips[i])
	//}
	//fmt.Println("Verify")
	//fmt.Printf("rpulppi.phi =\n")
	//for i := 0; i < len(delta_hats); i++ {
	//	for j := 0; j < len(delta_hats[i]); j++ {
	//		fmt.Printf("delta_hats[%d][%d] = %v\n", i, j, delta_hats[i][j])
	//	}
	//}
	//	seed_ch and ch
	preMsgAll := pp.collectBytesForRPULP2MLP(preMsg, rpulppi.psi, psip, rpulppi.phi, phips)
	seed_ch, err := Hash(preMsgAll)
	if err != nil {
		return false
	}
	if bytes.Compare(seed_ch, rpulppi.chseed) != 0 {
		return false
	}

	return true
}

// genUlpPolyCNTTsMLP is a helper function for rpulpProveMLP and rpulpVerifyMLP.
// reviewed on 2023.12.05
func (pp *PublicParameter) genUlpPolyCNTTsMLP(rpulpType RpUlpTypeMLP, binMatrixB [][]byte, nL uint8, nR uint8, gammas [][][]int64) (ps [][]*PolyCNTT, err error) {
	p := make([][]*PolyCNTT, pp.paramK)
	//	var tmp1, tmp2 big.Int

	switch rpulpType {
	case RpUlpTypeL0Rn:
		//	nL=0, nR >=2: A_{L0R2}
		// n := J
		if nL != 0 {
			return nil, fmt.Errorf("genUlpPolyCNTTsMLP: the rpulpType is RpUlpTypeL0Rn, but nL(%d) is not 0 as expected", nL)
		}
		n := nL + nR // // nL = 0, n = nL+nR = nR, note that the following computation is based on such a setting.
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			// p[t][0], ..., p[t][n-1]
			for j := uint8(0); j < n; j++ {
				// p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
				coeffs_r := make([]int64, pp.paramDC)
				for i := 0; i < pp.paramDC; i++ {
					coeffs_r[i] = gammas[t][0][i]
				}

				p[t][j] = &PolyCNTT{coeffs: coeffs_r}
			}

			//	p[t][n] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs_n := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				// F^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs_n[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_n[i] = reduceInt64(coeffs_n[i]-2*gammas[t][0][i]+gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_n[i] = reduceInt64(coeffs_n[i]-2*gammas[t][0][i]+gammas[t][1][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] + gammas[t][0][i]))
				//	//					coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*				tmp1.SetInt64(coeffs[i])
				//					tmp2.SetInt64(gammas[t][0][i-1])
				//					tmp2.Add(&tmp2, &tmp2)
				//					tmp1.Sub(&tmp1, &tmp2)
				//					tmp2.SetInt64(gammas[t][0][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs_n}

			// p[t][n+1]
			// p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
			coeffs_np1 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				coeffs_np1[i] = gammas[t][2][i]
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}
		}
	case RpUlpTypeL1Rn:
		//	(nL==1 AND nR >=2) OR ( nL==1 AND (nR===1 AND vRPub>0) ): A_{L1R2}
		// n := I + J
		if nL != 1 {
			return nil, fmt.Errorf("genUlpPolyCNTTsMLP: the rpulpType is RpUlpTypeL1Rn, but nL(%d) is not 1 as expected", nL)
		}
		n := nL + nR // n = 1+nR, note that the following computation is based on such a setting.
		n2 := n + 2
		// m = 3
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			// p[t][0]
			coeffs_l := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				coeffs_l[i] = gammas[t][0][i]
			}
			p[t][0] = &PolyCNTT{coeffs: coeffs_l}

			// p[t][1], ..., p[t][n-1]
			for j := uint8(1); j < n; j++ {
				coeffs_r := make([]int64, pp.paramDC)
				for i := 0; i < pp.paramDC; i++ {
					coeffs_r[i] = -gammas[t][0][i]
				}
				p[t][j] = &PolyCNTT{coeffs: coeffs_r}
			}

			//	p[t][n] = NTT^{-1}((-F)^T gamma[t][0] + F_1^T gamma[t][1] + B^T gamma[t][2])
			coeffs_n := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//(-F)^T[i] gamma[t][0] + F_1^T[i] gamma[t][1] + B^T[i] gamma[t][2]
				// B^T[i]: ith-col of B
				coeffs_n[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][2], pp.paramDC)

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of (-F)^T. i.e., the i-th column of (-F),
					//     is (0, ..., 0, 2, -1, 0, ..., 0), where 2 is the i-th coordinate and -1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_n[i] = reduceInt64(coeffs_n[i]+2*gammas[t][0][i]-gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of (-F)^T. i.e., the i-th column of (-F),
					//     is (0, ..., 0, 0, 0, 0, ..., 2), i.e., all zeros except the last coordinate is 2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_n[i] = reduceInt64(coeffs_n[i]+2*gammas[t][0][i]+gammas[t][1][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs[i] = pp.reduceBigInt(int64(coeffs[i] + gammas[t][1][i] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs[i] = reduceToQc()(int64(coeffs[i] + gammas[t][1][i] + 2*gammas[t][0][i-1] - gammas[t][0][i]))
				//	//coeffs[i] = reduceToQc(int64(coeffs[i]) + int64(gammas[t][1][i]) + 2*int64(gammas[t][0][i-1]) - int64(gammas[t][0][i]))
				//	coeffs[i] = reduceInt64(coeffs[i]+gammas[t][1][i]+2*gammas[t][0][i-1]-gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs[i])
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Sub(&tmp1, &tmp2)
				//						coeffs[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs_n}

			//	p[t][n+1]
			// p[t][n+1] = &PolyCNTT{coeffs: gammas[t][2]}
			coeffs_np1 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				coeffs_np1[i] = gammas[t][2][i]
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}
		}

	case RpUlpTypeLmRn:
		//	(nL>=2 AND nR >=1): A_{L2R2}
		// n := int(I + J)
		if nL < 2 {
			return nil, fmt.Errorf("genUlpPolyCNTTsMLP: the rpulpType is RpUlpTypeL1Rn, but nL(%d) is not >=2 as expected", nL)
		}
		n := nL + nR
		n2 := n + 4
		//	B : d rows 2d columns
		//	m = 5
		for t := 0; t < pp.paramK; t++ {
			p[t] = make([]*PolyCNTT, n2)

			// p[t][0], ..., p[t][nL-1]
			for j := uint8(0); j < nL; j++ {
				// p[t][j] = &PolyCNTT{coeffs: gammas[t][0]}
				coeffs_l := make([]int64, pp.paramDC)
				for i := 0; i < pp.paramDC; i++ {
					coeffs_l[i] = gammas[t][0][i]
				}
				p[t][j] = &PolyCNTT{coeffs: coeffs_l}
			}

			// p[t][nL], ..., p[t][nL+nR-1]
			for j := nL; j < nL+nR; j++ {
				// p[t][j] = &PolyCNTT{coeffs: gammas[t][1]}
				coeffs_r := make([]int64, pp.paramDC)
				for i := 0; i < pp.paramDC; i++ {
					coeffs_r[i] = gammas[t][1][i]
				}
				p[t][j] = &PolyCNTT{coeffs: coeffs_r}
			}

			// p[t][n] where n = nL+nR
			coeffs_n := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//coeffs_n[i] = reduceToQc(int64(-gammas[t][0][i]) + int64(-gammas[t][1][i]))
				coeffs_n[i] = reduceInt64(-gammas[t][0][i]-gammas[t][1][i], pp.paramQC)
				// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				/*				tmp1.SetInt64(-gammas[t][0][i])
								tmp2.SetInt64(-gammas[t][1][i])
								tmp1.Add(&tmp1, &tmp2)
								coeffs_n[i] = reduceBigInt(&tmp1, pp.paramQC)*/
			}
			p[t][n] = &PolyCNTT{coeffs: coeffs_n}

			//	p[t][n+1] = NTT^{-1}(F^T gamma[t][0] + F_1^T gamma[t][2] + B_1^T gamma[t][4])
			coeffs_np1 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][0] + F_1^T[i] gamma[t][2] + B^T[i] gamma[t][4]
				coeffs_np1[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, i), gammas[t][4], pp.paramDC)

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i]+gammas[t][0][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i]+gammas[t][2][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*				tmp1.SetInt64(coeffs_np1[i])
				//					tmp2.SetInt64(gammas[t][2][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					tmp2.SetInt64(gammas[t][0][i])
				//					tmp1.Add(&tmp1, &tmp2)
				//					coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np1[i])
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs_np1[i] = reduceToQc()(int64(coeffs_np1[i] + gammas[t][2][i] - 2*gammas[t][0][i-1] + gammas[t][0][i]))
				//	//coeffs_np1[i] = reduceToQc(int64(coeffs_np1[i]) + int64(gammas[t][2][i]) - 2*int64(gammas[t][0][i-1]) + int64(gammas[t][0][i]))
				//	coeffs_np1[i] = reduceInt64(coeffs_np1[i]+gammas[t][2][i]-2*gammas[t][0][i-1]+gammas[t][0][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np1[i])
				//						tmp2.SetInt64(gammas[t][2][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][0][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np1[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n+1] = &PolyCNTT{coeffs: coeffs_np1}

			//	p[t][n+2] = NTT^{-1}(F^T gamma[t][1] + F_1^T gamma[t][3] + B_2^T gamma[t][4])
			coeffs_np2 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				//F^T[i] gamma[t][1] + F_1^T[i] gamma[t][3] + B_2^T[i] gamma[t][4]
				coeffs_np2[i] = pp.intVecInnerProductWithReductionQc(getMatrixColumn(binMatrixB, pp.paramDC, pp.paramDC+i), gammas[t][4], pp.paramDC)

				if i < pp.paramDC-1 {
					// i=0, ... d_c-2
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, -2, 1, 0, ..., 0), where -2 is the i-th coordinate and 1 is the (i+1)-th.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 0), i.e., all zeros.
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i]+gammas[t][1][i+1], pp.paramQC)
					// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				} else {
					// i = d_c -1
					// The i-th row of F^T. i.e., the i-th column of F,
					//     is (0, ..., 0, 0, 0, 0, ..., -2), i.e., all zeros except the last coordinate is -2.
					// The i-th row of F_1^T. i.e., the i-th column of F_1,
					//     is (0, ..., 1), i.e., all zeros, except the last coordinate is 1.
					coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i]+gammas[t][3][i], pp.paramQC)
				}

				//if i == 0 {
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][3][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else if i < (pp.paramN - 1) {
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][1][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//} else { // i in [N-1, d-1]
				//	//coeffs_np2[i] = reduceToQc()(int64(coeffs_np2[i] + gammas[t][3][i] - 2*gammas[t][1][i-1] + gammas[t][1][i]))
				//	//coeffs_np2[i] = reduceToQc(int64(coeffs_np2[i]) + int64(gammas[t][3][i]) - 2*int64(gammas[t][1][i-1]) + int64(gammas[t][1][i]))
				//	coeffs_np2[i] = reduceInt64(coeffs_np2[i]+gammas[t][3][i]-2*gammas[t][1][i-1]+gammas[t][1][i], pp.paramQC)
				//	// the addition of three numbers in [-(q_c-1)/2, (q_c-1)/] will not overflow
				//	/*					tmp1.SetInt64(coeffs_np2[i])
				//						tmp2.SetInt64(gammas[t][3][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i-1])
				//						tmp2.Add(&tmp2, &tmp2)
				//						tmp1.Sub(&tmp1, &tmp2)
				//						tmp2.SetInt64(gammas[t][1][i])
				//						tmp1.Add(&tmp1, &tmp2)
				//						coeffs_np2[i] = reduceBigInt(&tmp1, pp.paramQC)*/
				//}
			}
			p[t][n+2] = &PolyCNTT{coeffs: coeffs_np2}

			// p[t][n+3]
			// p[t][n+3] = &PolyCNTT{coeffs: gammas[t][4]}
			coeffs_np3 := make([]int64, pp.paramDC)
			for i := 0; i < pp.paramDC; i++ {
				coeffs_np3[i] = gammas[t][4][i]
			}
			p[t][n+3] = &PolyCNTT{coeffs: coeffs_np3}
		}
	}

	return p, nil
}

// collectBytesForRPULP1MLP is a helper function for rpulpProveMLP and rpulpVerifyMLP.
// reviewed on 2023.12.05
func (pp *PublicParameter) collectBytesForRPULP1MLP(message []byte, cmts []*ValueCommitment, n uint8,
	b_hat *PolyCNTTVec, c_hats []*PolyCNTT, n2 uint8, n1 uint8,
	rpulpType RpUlpTypeMLP, binMatrixB [][]byte, nL uint8, nR uint8, m uint8, u_hats [][]int64,
	c_waves []*PolyCNTT, c_hat_g *PolyCNTT, cmt_ws [][]*PolyCNTTVec,
	delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT, ws []*PolyCNTTVec) []byte {

	length := len(message) + // message
		int(n)*(pp.paramKC+1)*pp.paramDC*8 + // cmts []*ValueCommitment length 8, (k_c+1) PolyCNTT
		1 + // n
		pp.paramKC*pp.paramDC*8 + // b_hat *PolyCNTTVec, length K_c
		int(n2)*pp.paramDC*8 + // c_hats length n2 PolyCNTT
		1 + 1 + // n2, n1
		1 + // rpulpType
		len(binMatrixB)*len(binMatrixB[0]) + 1 + 1 + 1 + // binMatrixB [][]byte, nL uint8, nR uint8, m uint8
		int(m)*pp.paramDC*8 + // u_hats [][]int64
		int(n)*pp.paramDC*8 + // c_waves []*PolyCNTT, length n
		pp.paramDC*8 + // c_hat_g *PolyCNTT
		pp.paramK*int(n)*(pp.paramKC*pp.paramDC*8) + // cmt_ws [][]*PolyCNTTVec
		pp.paramK*int(n)*pp.paramDC*8*2 + // delta_waves [][]*PolyCNTT, delta_hats [][]*PolyCNTT,
		pp.paramK*(pp.paramKC*pp.paramDC*8) // ws []*PolyCNTTVec

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
	appendInt64ToBytes := func(a int64) {
		rst = append(rst, byte(a>>0))
		rst = append(rst, byte(a>>8))
		rst = append(rst, byte(a>>16))
		rst = append(rst, byte(a>>24))
		rst = append(rst, byte(a>>32))
		rst = append(rst, byte(a>>40))
		rst = append(rst, byte(a>>48))
		rst = append(rst, byte(a>>56))
	}

	// message
	rst = append(rst, message...)

	//	cmts with length n
	for i := 0; i < len(cmts); i++ {
		for j := 0; j < len(cmts[i].b.polyCNTTs); j++ {
			appendPolyNTTToBytes(cmts[i].b.polyCNTTs[j])
		}
		appendPolyNTTToBytes(cmts[i].c)
	}

	//	n uint8
	rst = append(rst, n)

	// b_hat
	for i := 0; i < len(b_hat.polyCNTTs); i++ {
		appendPolyNTTToBytes(b_hat.polyCNTTs[i])
	}
	// c_hats []*PolyCNTT with length n2
	for i := 0; i < len(c_hats); i++ {
		appendPolyNTTToBytes(c_hats[i])
	}

	//	n2 uint8
	rst = append(rst, n2)

	//	n1 uint8
	rst = append(rst, n1)

	//TODO_DONE:A = ulpType B I J m
	rst = append(rst, byte(rpulpType))
	// B
	appendBinaryMartix := func(data [][]byte) {
		for i := 0; i < len(data); i++ {
			rst = append(rst, data[i]...)
		}
	}
	appendBinaryMartix(binMatrixB)
	// nL
	rst = append(rst, nL)
	// nR
	rst = append(rst, nR)

	// m
	rst = append(rst, m)

	//u_hats length m
	for i := 0; i < len(u_hats); i++ {
		for j := 0; j < len(u_hats[i]); j++ {
			appendInt64ToBytes(u_hats[i][j])
		}
	}

	//c_waves
	for i := 0; i < len(c_waves); i++ {
		appendPolyNTTToBytes(c_waves[i])
	}

	//c_hat_g [n2+1]
	appendPolyNTTToBytes(c_hat_g)

	// cmt_ws [][]*PolyCNTTVec
	for i := 0; i < len(cmt_ws); i++ {
		for j := 0; j < len(cmt_ws[i]); j++ {
			for k := 0; k < len(cmt_ws[i][j].polyCNTTs); k++ {
				appendPolyNTTToBytes(cmt_ws[i][j].polyCNTTs[k])
			}
		}
	}

	// delta_waves [][]*PolyCNTT
	for i := 0; i < len(delta_waves); i++ {
		for j := 0; j < len(delta_waves[i]); j++ {
			appendPolyNTTToBytes(delta_waves[i][j])
		}
	}
	// delta_hats [][]*PolyCNTT
	for i := 0; i < len(delta_hats); i++ {
		for j := 0; j < len(delta_hats[i]); j++ {
			appendPolyNTTToBytes(delta_hats[i][j])

		}
	}

	// ws []*PolyCNTTVec
	for i := 0; i < len(ws); i++ {
		for j := 0; j < len(ws[i].polyCNTTs); j++ {
			appendPolyNTTToBytes(ws[i].polyCNTTs[j])
		}
	}

	return rst
}

// collectBytesForRPULP2MLP is a helper function for rpulpProveMLP and rpulpVerifyMLP.
// reviewed on 2023.12.05
func (pp *PublicParameter) collectBytesForRPULP2MLP(
	preMsg []byte,
	psi *PolyCNTT, psip *PolyCNTT, phi *PolyCNTT, phips []*PolyCNTT) []byte {

	length := len(preMsg) + 3*pp.paramDC*8 + len(phips)*pp.paramDC*8
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

	// preMsg
	rst = append(rst, preMsg...)

	// psi
	appendPolyNTTToBytes(psi)

	// psip
	appendPolyNTTToBytes(psip)

	// phi
	appendPolyNTTToBytes(phi)

	// phips
	for i := 0; i < len(phips); i++ {
		appendPolyNTTToBytes(phips[i])
	}
	return rst
}

// rpulpProofMLPSerializeSizeByCommNum returns the serialized size for a range and balance proof among n commitments.
// Input two params nL and nR, rather than n = nL + nR, to avoid confusion.
// finished and review on 2023.12.04
// reviewed on 2023.12.05
func (pp *PublicParameter) rpulpProofMLPSerializeSizeByCommNum(nL uint8, nR uint8) int {
	lengthOfPolyCNTT := pp.PolyCNTTSerializeSize()

	n := nL + nR
	length := 3 + //	rpUlpType, nL, nR
		int(n)*lengthOfPolyCNTT + // c_waves   []*PolyCNTT, with length n
		3*lengthOfPolyCNTT + // c_hat_g,psi,phi  *PolyCNTT
		HashOutputBytesLen + // chseed    []byte
		pp.paramK*int(n)*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) + // cmt_zs    [][]*PolyCVec: dimension [pp.paramK][n], each is a PolyCVec with vevLen = paramLc, i.e., (S_{eta_c - beta_c})^{L_c}
		pp.paramK*pp.PolyCVecSerializeSizeEtaByVecLen(pp.paramLC) //	zs        []*PolyCVec: dimension [pp.paramK], each is a PolyCVec with vevLen = paramLc, i.e., (S_{eta_c - beta_c})^{L_c}

	return length
}

// serializeRpulpProofMLP serialize the input rpulpProofMLP to []byte.
// finished and review on 2023.12.04
// reviewed on 2023.12.05
func (pp *PublicParameter) serializeRpulpProofMLP(prf *RpulpProofMLP) ([]byte, error) {
	if prf == nil || prf.c_waves == nil ||
		prf.c_hat_g == nil || prf.psi == nil || prf.phi == nil ||
		len(prf.chseed) == 0 ||
		prf.cmt_zs == nil || prf.zs == nil {
		return nil, errors.New("SerializeRpulpProofMLP: there is nil pointer in the input rpulpProofMLP")
	}

	var err error
	length := pp.rpulpProofMLPSerializeSizeByCommNum(prf.nL, prf.nR)
	w := bytes.NewBuffer(make([]byte, 0, length))

	// rpUlpType RpUlpTypeMLP
	err = w.WriteByte(byte(prf.rpUlpType))
	if err != nil {
		return nil, err
	}

	// nL        uint8
	err = w.WriteByte(byte(prf.nL))
	if err != nil {
		return nil, err
	}

	// nR        uint8
	err = w.WriteByte(byte(prf.nR))
	if err != nil {
		return nil, err
	}

	n := int(prf.nL + prf.nR)

	// c_waves []*PolyCNTT; length n
	for i := 0; i < n; i++ {
		err = pp.writePolyCNTT(w, prf.c_waves[i])
		if err != nil {
			return nil, err
		}
	}

	//c_hat_g *PolyCNTT
	err = pp.writePolyCNTT(w, prf.c_hat_g)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.psi)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	err = pp.writePolyCNTT(w, prf.phi)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	_, err = w.Write(prf.chseed)
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCVec eta: dimension [paramK][n]
	for i := 0; i < pp.paramK; i++ {
		for j := 0; j < n; j++ {
			err = pp.writePolyCVecEta(w, prf.cmt_zs[i][j])
			if err != nil {
				return nil, err
			}
		}
	}

	//zs      []*PolyCVec eta: dimension [paramK]
	for i := 0; i < pp.paramK; i++ {
		err = pp.writePolyCVecEta(w, prf.zs[i])
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// deserializeRpulpProofMLP deserialize the input serializedRpulpProofMLP to a rpulpProofMLP
// finished and review on 2023.12.04
// reviewed on 2023.12.05
func (pp *PublicParameter) deserializeRpulpProofMLP(serializedRpulpProofMLP []byte) (*RpulpProofMLP, error) {

	r := bytes.NewReader(serializedRpulpProofMLP)

	// rpUlpType RpUlpTypeMLP
	rpUlpType, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// nL        uint8
	nL, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// nR        uint8
	nR, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	n := int(nL + nR)

	// c_waves []*PolyCNTT; length n
	c_waves := make([]*PolyCNTT, n)
	for i := 0; i < n; i++ {
		c_waves[i], err = pp.readPolyCNTT(r)
		if err != nil {
			return nil, err
		}
	}

	//c_hat_g *PolyCNTT
	c_hat_g, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//psi     *PolyCNTT
	psi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//phi     *PolyCNTT
	phi, err := pp.readPolyCNTT(r)
	if err != nil {
		return nil, err
	}

	//chseed  []byte
	chseed := make([]byte, HashOutputBytesLen)
	_, err = r.Read(chseed)
	if err != nil {
		return nil, err
	}

	//cmt_zs  [][]*PolyCVec eta: dimension [paramK][n]
	cmt_zs := make([][]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		cmt_zs[i] = make([]*PolyCVec, n)
		for j := 0; j < n; j++ {
			cmt_zs[i][j], err = pp.readPolyCVecEta(r)
			if err != nil {
				return nil, err
			}
		}
	}

	//zs      []*PolyCVec eta: dimension [paramK]
	zs := make([]*PolyCVec, pp.paramK)
	for i := 0; i < pp.paramK; i++ {
		zs[i], err = pp.readPolyCVecEta(r)
		if err != nil {
			return nil, err
		}
	}

	return &RpulpProofMLP{
		rpUlpType: RpUlpTypeMLP(rpUlpType),
		nL:        nL,
		nR:        nR,
		c_waves:   c_waves,
		c_hat_g:   c_hat_g,
		psi:       psi,
		phi:       phi,
		chseed:    chseed,
		cmt_zs:    cmt_zs,
		zs:        zs,
	}, nil
}

//func (pp *PublicParameter) decideRpUlpType(nL uint8, nR uint8, vRPub uint64) (RpUlpTypeMLP, error) {
//	if int(nL) > pp.paramI || int(nR) > pp.paramJ {
//		return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the input nL(%d) or nR(%d) exceeds the allowed maximum scope [0, %d] (input-side), [0, %d] (output-side)", nL, nR, pp.paramI, pp.paramJ)
//	}
//	if nL == 0 {
//		if nR == 0 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) does not need RpUlpProve", nL, nR)
//		} else if nR == 1 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) does not need RpUlpProve", nL, nR)
//		} else {
//			// nR >= 2
//			return RpUlpTypeL0Rn, nil
//		}
//	} else if nL == 1 {
//		if nR == 0 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) does not need RpUlpProve", nL, nR)
//		} else if nR == 1 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) does not need RpUlpProve", nL, nR)
//		} else {
//			// nR >= 2
//			return RpUlpTypeL1Rn, nil
//		}
//	} else {
//		// nL >= 2
//		if nR == 0 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) should implemented by (nL=%d, nR=%d)", nL, nR, nR, nL)
//		} else if nR == 1 {
//			return RpUlpTypeL0Rn, fmt.Errorf("decideRpUlpType: the case of (nL=%d, nR=%d) does not need RpUlpProve", nL, nR)
//		} else {
//			// nR >= 2
//			return RpUlpTypeLmRn, nil
//		}
//	}
//}

//	BPF		end
